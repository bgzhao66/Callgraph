#include "callgraph/elf_resolver.h"

#include <elf.h>
#include <fcntl.h>
#include <gelf.h>
#include <libelf.h>
#include <unistd.h>

#ifdef CALLGRAPH_HAVE_LIBOPCODES
#include <dis-asm.h>
#endif
#include <elfutils/libdwfl.h>

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <map>
#include <optional>
#include <utility>
#include <vector>

#include "callgraph/common.h"

namespace callgraph {
namespace {

struct ElfFile {
    int fd = -1;
    Elf* elf = nullptr;

    ~ElfFile()
    {
        if (elf)
            elf_end(elf);
        if (fd >= 0)
            close(fd);
    }
};

struct Segment {
    uint64_t vaddr;
    uint64_t memsz;
    uint64_t offset;
    uint64_t filesz;
};

std::optional<uint64_t> file_offset_for(const std::vector<Segment>& segments,
                                        uint64_t vaddr)
{
    for (const auto& seg : segments) {
        if (vaddr >= seg.vaddr && vaddr < seg.vaddr + seg.filesz)
            return seg.offset + (vaddr - seg.vaddr);
    }
    return std::nullopt;
}

std::string build_id_of(Elf* elf)
{
    size_t shstrndx = 0;
    if (elf_getshdrstrndx(elf, &shstrndx) != 0)
        return {};

    Elf_Scn* scn = nullptr;
    while ((scn = elf_nextscn(elf, scn)) != nullptr) {
        GElf_Shdr shdr;
        if (!gelf_getshdr(scn, &shdr))
            continue;

        const char* name = elf_strptr(elf, shstrndx, shdr.sh_name);
        if (!name || strcmp(name, ".note.gnu.build-id") != 0)
            continue;

        Elf_Data* data = elf_getdata(scn, nullptr);
        if (!data)
            continue;

        size_t off = 0;
        while (off < data->d_size) {
            GElf_Nhdr nhdr;
            size_t name_off = 0;
            size_t desc_off = 0;
            const size_t next = gelf_getnote(data, off, &nhdr, &name_off, &desc_off);
            if (next == 0)
                break;

            const char* note_name = static_cast<const char*>(data->d_buf) + name_off;
            if (nhdr.n_type == NT_GNU_BUILD_ID && nhdr.n_namesz == 4 &&
                memcmp(note_name, "GNU", 4) == 0) {
                const auto* desc =
                    static_cast<const uint8_t*>(data->d_buf) + desc_off;
                return hex_encode(desc, nhdr.n_descsz);
            }
            off = next;
        }
    }
    return {};
}

int binding_rank(const GElf_Sym& sym)
{
    switch (GELF_ST_BIND(sym.st_info)) {
    case STB_GLOBAL:
        return 2;
    case STB_WEAK:
        return 1;
    default:
        return 0;
    }
}

#ifdef CALLGRAPH_HAVE_LIBOPCODES
namespace {

int discard_printf(void*, const char*, ...)
{
    return 0;
}

int read_code(bfd_vma memaddr, bfd_byte* myaddr, unsigned int length,
              struct disassemble_info* info)
{
    if (memaddr < info->buffer_vma ||
        memaddr + length > info->buffer_vma + info->buffer_length)
        return -1;
    memcpy(myaddr, info->buffer + (memaddr - info->buffer_vma), length);
    return 0;
}

bool is_return_instruction(const unsigned char* bytes, int length)
{
    if (length <= 0)
        return false;

    // Skip legacy/REX prefixes before checking the opcode byte.
    int index = 0;
    while (index < length &&
           (bytes[index] == 0x66 || bytes[index] == 0x67 ||
            bytes[index] == 0xf2 || bytes[index] == 0xf3 ||
            (bytes[index] >= 0x40 && bytes[index] <= 0x4f))) {
        ++index;
    }
    if (index >= length)
        return false;

    // ret / retf
    if (bytes[index] == 0xc3 || bytes[index] == 0xcb)
        return true;
    // ret imm16 / retf imm16
    if (bytes[index] == 0xc2 || bytes[index] == 0xca)
        return length - index >= 3;
    return false;
}

// Uretprobes hijack the return address and break C++ unwinding.  Attaching a
// normal uprobe to each `ret` instruction avoids that, at the cost of more
// probes and no event for frames unwound without executing a return.
void scan_return_instructions(int fd, FunctionInfo& info, bool is_64bit)
{
    if (info.high_pc <= info.low_pc)
        return;

    const uint64_t size = info.high_pc - info.low_pc;
    if (size > (16u << 20))
        return;

    std::vector<unsigned char> code(static_cast<size_t>(size));
    const ssize_t got = pread(fd, code.data(), code.size(), info.file_offset);
    if (got <= 0)
        return;
    code.resize(static_cast<size_t>(got));

    struct disassemble_info dis;
    init_disassemble_info(&dis, nullptr, discard_printf);
    dis.arch = bfd_arch_i386;
    dis.mach = is_64bit ? bfd_mach_x86_64 : bfd_mach_i386_i386;
    dis.endian = BFD_ENDIAN_LITTLE;
    dis.buffer = code.data();
    dis.buffer_length = code.size();
    dis.buffer_vma = info.low_pc;
    dis.read_memory_func = read_code;

    disassembler_ftype disassemble =
        disassembler(bfd_arch_i386, false, dis.mach, nullptr);
    if (!disassemble)
        return;

    bfd_vma pc = info.low_pc;
    const bfd_vma end = info.low_pc + code.size();
    while (pc < end) {
        const int length = disassemble(pc, &dis);
        if (length <= 0)
            break;

        const size_t index = static_cast<size_t>(pc - info.low_pc);
        if (index < code.size() &&
            is_return_instruction(code.data() + index, length)) {
            info.return_offsets.push_back(info.file_offset + index);
        }
        pc += static_cast<bfd_vma>(length);
    }

    std::sort(info.return_offsets.begin(), info.return_offsets.end());
    info.return_offsets.erase(
        std::unique(info.return_offsets.begin(), info.return_offsets.end()),
        info.return_offsets.end());
}

}  // namespace
#endif

bool has_section(Elf* elf, const char* wanted)
{
    size_t shstrndx = 0;
    if (elf_getshdrstrndx(elf, &shstrndx) != 0)
        return false;

    Elf_Scn* scn = nullptr;
    while ((scn = elf_nextscn(elf, scn)) != nullptr) {
        GElf_Shdr shdr;
        if (!gelf_getshdr(scn, &shdr))
            continue;
        const char* name = elf_strptr(elf, shstrndx, shdr.sh_name);
        if (name && strcmp(name, wanted) == 0)
            return true;
    }
    return false;
}

void add_function(std::map<uint64_t, std::pair<FunctionInfo, int>>& by_offset,
                  const std::vector<Segment>& segments, uint64_t vaddr,
                  uint64_t size, const char* raw, int rank,
                  const std::string& path)
{
    const auto offset = file_offset_for(segments, vaddr);
    if (!offset)
        return;

    FunctionInfo info;
    info.name = demangle_symbol(raw);
    info.linkage_name = raw;
    info.low_pc = vaddr;
    info.high_pc = vaddr + size;
    info.file_offset = *offset;
    info.module_path = path;

    auto it = by_offset.find(*offset);
    if (it == by_offset.end()) {
        by_offset.emplace(*offset, std::make_pair(std::move(info), rank));
    } else if (rank > it->second.second) {
        it->second = std::make_pair(std::move(info), rank);
    }
}

ModuleInfo build_module(
    const std::string& path, const std::string& build_id,
    bool has_exception_tables,
    std::map<uint64_t, std::pair<FunctionInfo, int>>& by_offset, int fd,
    bool scan_returns, bool is_64bit)
{
    (void)fd;
    (void)scan_returns;
    (void)is_64bit;

    ModuleInfo module;
    module.path = path;
    module.build_id = build_id;
    module.has_exception_tables = has_exception_tables;
    module.functions.reserve(by_offset.size());

    for (auto& entry : by_offset) {
#ifdef CALLGRAPH_HAVE_LIBOPCODES
        if (scan_returns)
            scan_return_instructions(fd, entry.second.first, is_64bit);
#endif
        module.functions.push_back(std::move(entry.second.first));
    }
    return module;
}

ModuleInfo resolve_with_dwfl(const std::string& path)
{
    Dwfl_Callbacks callbacks = {};
    callbacks.find_elf = dwfl_build_id_find_elf;
    callbacks.find_debuginfo = dwfl_standard_find_debuginfo;
    callbacks.section_address = dwfl_offline_section_address;
    callbacks.debuginfo_path = nullptr;

    Dwfl* dwfl = dwfl_begin(&callbacks);
    if (!dwfl)
        fail("libdwfl initialization failed: %s", dwfl_errmsg(-1));

    struct DwflGuard {
        Dwfl* dwfl;
        ~DwflGuard() { dwfl_end(dwfl); }
    } guard{dwfl};

    Dwfl_Module* module =
        dwfl_report_offline(dwfl, path.c_str(), path.c_str(), -1);
    if (!module)
        fail("cannot read %s: %s", path.c_str(), dwfl_errmsg(-1));
    if (dwfl_report_end(dwfl, nullptr, nullptr) != 0)
        fail("cannot finalize %s: %s", path.c_str(), dwfl_errmsg(-1));

    GElf_Addr module_bias = 0;
    Elf* elf = dwfl_module_getelf(module, &module_bias);
    if (!elf)
        fail("cannot read ELF %s: %s", path.c_str(), dwfl_errmsg(-1));
    GElf_Ehdr ehdr;
    if (!gelf_getehdr(elf, &ehdr))
        fail("cannot read ELF header of %s", path.c_str());

    std::vector<Segment> exec_segments;
    size_t phnum = 0;
    if (elf_getphdrnum(elf, &phnum) != 0)
        fail("cannot read program headers of %s", path.c_str());
    for (size_t i = 0; i < phnum; ++i) {
        GElf_Phdr phdr;
        if (!gelf_getphdr(elf, i, &phdr))
            continue;
        if (phdr.p_type != PT_LOAD || !(phdr.p_flags & PF_X))
            continue;
        exec_segments.push_back(
            {phdr.p_vaddr, phdr.p_memsz, phdr.p_offset, phdr.p_filesz});
    }
    if (exec_segments.empty())
        fail("%s has no executable PT_LOAD segment", path.c_str());

    const int symbol_count = dwfl_module_getsymtab(module);
    if (symbol_count <= 0)
        fail("%s has no usable symbol table and no external debug information",
             path.c_str());

    std::map<uint64_t, std::pair<FunctionInfo, int>> by_offset;

    for (int i = 0; i < symbol_count; ++i) {
        GElf_Sym sym;
        GElf_Addr address = 0;
        GElf_Word shndx = 0;
        Elf* symbol_elf = nullptr;
        Dwarf_Addr symbol_bias = 0;

        const char* raw = dwfl_module_getsym_info(
            module, i, &sym, &address, &shndx, &symbol_elf, &symbol_bias);
        if (!raw || !*raw)
            continue;
        if (GELF_ST_TYPE(sym.st_info) != STT_FUNC)
            continue;
        if (address == 0)
            continue;
        if (strstr(raw, "@plt") != nullptr)
            continue;

        // Find the main-ELF section containing the adjusted address so that
        // symbols coming from a separate .debug file are still validated.
        Dwarf_Addr section_address = address;
        Dwarf_Addr section_bias = 0;
        Elf_Scn* section =
            dwfl_module_address_section(module, &section_address, &section_bias);
        if (!section)
            continue;
        GElf_Shdr section_header;
        if (!gelf_getshdr(section, &section_header))
            continue;
        if (!(section_header.sh_flags & SHF_EXECINSTR))
            continue;

        // dwfl reports offline modules at a synthetic base (usually 0x10000
        // for PIE); the address it returns is adjusted by that bias, while
        // uprobe offsets and PT_LOAD vaddrs are file-relative.
        if (address < module_bias)
            continue;
        const uint64_t file_vaddr = address - module_bias;

        add_function(by_offset, exec_segments, file_vaddr, sym.st_size, raw,
                     binding_rank(sym), path);
    }

    if (by_offset.empty())
        fail("%s has no instrumentable functions (debug information missing?)",
             path.c_str());

    const bool is_64bit = ehdr.e_machine == EM_X86_64;
    const bool is_x86 = is_64bit || ehdr.e_machine == EM_386;

    int fd = -1;
    bool scan_returns = false;
#ifdef CALLGRAPH_HAVE_LIBOPCODES
    if (is_x86) {
        fd = open(path.c_str(), O_RDONLY | O_CLOEXEC);
        scan_returns = fd >= 0;
    }
#else
    (void)is_x86;
#endif

    ModuleInfo result =
        build_module(path, build_id_of(elf),
                     has_section(elf, ".gcc_except_table"), by_offset, fd,
                     scan_returns, is_64bit);
    if (fd >= 0)
        close(fd);
    return result;
}

}  // namespace

ModuleInfo ElfResolver::resolve(const std::string& path)
{
    if (elf_version(EV_CURRENT) == EV_NONE)
        fail("libelf initialization failed");

    ElfFile file;
    file.fd = open(path.c_str(), O_RDONLY | O_CLOEXEC);
    if (file.fd < 0)
        fail("cannot open %s: %s", path.c_str(), errno_string(errno).c_str());

    file.elf = elf_begin(file.fd, ELF_C_READ_MMAP, nullptr);
    if (!file.elf)
        fail("cannot read ELF %s: %s", path.c_str(), elf_errmsg(-1));

    GElf_Ehdr ehdr;
    if (!gelf_getehdr(file.elf, &ehdr))
        fail("cannot read ELF header of %s", path.c_str());
    if (ehdr.e_type != ET_EXEC && ehdr.e_type != ET_DYN)
        fail("%s is not an executable or shared object", path.c_str());

    std::vector<Segment> exec_segments;
    size_t phnum = 0;
    if (elf_getphdrnum(file.elf, &phnum) != 0)
        fail("cannot read program headers of %s", path.c_str());

    for (size_t i = 0; i < phnum; ++i) {
        GElf_Phdr phdr;
        if (!gelf_getphdr(file.elf, i, &phdr))
            continue;
        if (phdr.p_type != PT_LOAD || !(phdr.p_flags & PF_X))
            continue;
        exec_segments.push_back(
            {phdr.p_vaddr, phdr.p_memsz, phdr.p_offset, phdr.p_filesz});
    }
    if (exec_segments.empty())
        fail("%s has no executable PT_LOAD segment", path.c_str());

    size_t shnum = 0;
    if (elf_getshdrnum(file.elf, &shnum) != 0)
        fail("cannot read section headers of %s", path.c_str());

    std::vector<bool> executable_section(shnum, false);
    Elf_Scn* symtab_scn = nullptr;
    GElf_Shdr symtab_shdr{};
    bool has_exception_tables = false;

    size_t shstrndx = 0;
    const bool have_shstrndx =
        elf_getshdrstrndx(file.elf, &shstrndx) == 0;

    Elf_Scn* scn = nullptr;
    while ((scn = elf_nextscn(file.elf, scn)) != nullptr) {
        GElf_Shdr shdr;
        if (!gelf_getshdr(scn, &shdr))
            continue;

        const size_t index = elf_ndxscn(scn);
        if (index < shnum)
            executable_section[index] = (shdr.sh_flags & SHF_EXECINSTR) != 0;

        if (have_shstrndx) {
            const char* section_name =
                elf_strptr(file.elf, shstrndx, shdr.sh_name);
            if (section_name && strcmp(section_name, ".gcc_except_table") == 0)
                has_exception_tables = true;
        }

        if (shdr.sh_type == SHT_SYMTAB && symtab_scn == nullptr) {
            symtab_scn = scn;
            symtab_shdr = shdr;
        }
    }

    if (symtab_scn == nullptr)
        return resolve_with_dwfl(path);

    Elf_Data* symdata = elf_getdata(symtab_scn, nullptr);
    if (!symdata)
        fail("cannot read .symtab of %s", path.c_str());

    if (symtab_shdr.sh_entsize == 0)
        fail("malformed .symtab in %s", path.c_str());

    const size_t symbol_count = symtab_shdr.sh_size / symtab_shdr.sh_entsize;
    std::map<uint64_t, std::pair<FunctionInfo, int>> by_offset;

    for (size_t i = 0; i < symbol_count; ++i) {
        GElf_Sym sym;
        if (!gelf_getsym(symdata, i, &sym))
            continue;

        if (GELF_ST_TYPE(sym.st_info) != STT_FUNC)
            continue;
        if (sym.st_shndx == SHN_UNDEF || sym.st_shndx >= SHN_LORESERVE)
            continue;
        if (sym.st_shndx >= executable_section.size() ||
            !executable_section[sym.st_shndx])
            continue;
        if (sym.st_value == 0)
            continue;

        const char* raw = elf_strptr(file.elf, symtab_shdr.sh_link, sym.st_name);
        if (!raw || !*raw)
            continue;
        if (strstr(raw, "@plt") != nullptr)
            continue;

        add_function(by_offset, exec_segments, sym.st_value, sym.st_size, raw,
                     binding_rank(sym), path);
    }

#ifdef CALLGRAPH_HAVE_LIBOPCODES
    const bool is_x86 = ehdr.e_machine == EM_X86_64 || ehdr.e_machine == EM_386;
    const bool is_64bit = ehdr.e_machine == EM_X86_64;
#else
    const bool is_x86 = false;
    const bool is_64bit = false;
#endif

    return build_module(path, build_id_of(file.elf), has_exception_tables,
                        by_offset, file.fd, is_x86, is_64bit);
}

}  // namespace callgraph
