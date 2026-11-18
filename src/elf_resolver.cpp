#include "callgraph/elf_resolver.h"

#include <elf.h>
#include <fcntl.h>
#include <gelf.h>
#include <libelf.h>
#include <unistd.h>

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

// Go keeps these sections even when built with -ldflags="-s -w".
bool is_go_binary(Elf* elf)
{
    return has_section(elf, ".note.go.buildid") ||
           has_section(elf, ".go.buildinfo");
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
    bool has_exception_tables, bool go_binary,
    std::map<uint64_t, std::pair<FunctionInfo, int>>& by_offset)
{
    ModuleInfo module;
    module.path = path;
    module.build_id = build_id;
    module.has_exception_tables = has_exception_tables;
    module.is_go_binary = go_binary;
    module.functions.reserve(by_offset.size());

    for (auto& entry : by_offset) {
        entry.second.first.module_build_id = build_id;
        module.functions.push_back(std::move(entry.second.first));
    }
    return module;
}

void annotate_source_info(const std::string& path,
                          std::vector<FunctionInfo>& functions)
{
    if (functions.empty())
        return;

    Dwfl_Callbacks callbacks = {};
    callbacks.find_elf = dwfl_build_id_find_elf;
    callbacks.find_debuginfo = dwfl_standard_find_debuginfo;
    callbacks.section_address = dwfl_offline_section_address;
    callbacks.debuginfo_path = nullptr;

    Dwfl* dwfl = dwfl_begin(&callbacks);
    if (!dwfl)
        return;

    struct DwflGuard {
        Dwfl* dwfl;
        ~DwflGuard() { dwfl_end(dwfl); }
    } guard{dwfl};

    Dwfl_Module* module =
        dwfl_report_offline(dwfl, path.c_str(), path.c_str(), -1);
    if (!module)
        return;
    if (dwfl_report_end(dwfl, nullptr, nullptr) != 0)
        return;

    GElf_Addr module_bias = 0;
    if (!dwfl_module_getelf(module, &module_bias))
        return;

    for (auto& function : functions) {
        Dwfl_Line* line =
            dwfl_module_getsrc(module, function.low_pc + module_bias);
        if (!line)
            continue;

        Dwarf_Addr address = 0;
        int line_number = 0;
        const char* file = dwfl_lineinfo(line, &address, &line_number, nullptr,
                                         nullptr, nullptr);
        if (!file || !*file)
            continue;

        std::string source = file;
        const char* compile_dir = dwfl_line_comp_dir(line);
        if (!source.empty() && source.front() != '/' && compile_dir &&
            *compile_dir) {
            source = std::string(compile_dir) + "/" + source;
        }
        function.source_file = std::move(source);
        function.source_line = line_number > 0 ? line_number : 0;
    }
}

ModuleInfo resolve_with_dwfl(const std::string& path,
                             const ResolveOptions& options)
{    Dwfl_Callbacks callbacks = {};
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
    if (symbol_count <= 0) {
        if (is_go_binary(elf)) {
            fail("%s is a Go binary without a usable symbol table; binaries "
                 "built with -ldflags=\"-s -w\" cannot be traced",
                 path.c_str());
        }
        fail("%s has no usable symbol table and no external debug information",
             path.c_str());
    }

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

    ModuleInfo result =
        build_module(path, build_id_of(elf),
                     has_section(elf, ".gcc_except_table"), is_go_binary(elf),
                     by_offset);
    if (options.annotate_source)
        annotate_source_info(path, result.functions);
    return result;
}

}  // namespace

ModuleInfo ElfResolver::resolve(const std::string& path,
                                const ResolveOptions& options)
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
        return resolve_with_dwfl(path, options);

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

    ModuleInfo result =
        build_module(path, build_id_of(file.elf), has_exception_tables,
                     is_go_binary(file.elf), by_offset);
    if (options.annotate_source)
        annotate_source_info(path, result.functions);
    return result;
}

}  // namespace callgraph
