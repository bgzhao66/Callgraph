#include "callgraph/static_call_graph.h"

#include <elf.h>
#include <fcntl.h>
#include <gelf.h>
#include <libelf.h>
#include <unistd.h>

#ifdef CALLGRAPH_HAVE_LIBOPCODES
#include <dis-asm.h>
#endif

#include <algorithm>
#include <cctype>
#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <deque>
#include <limits>
#include <optional>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

namespace callgraph {
namespace {

constexpr uint64_t kInf = std::numeric_limits<uint64_t>::max();
constexpr size_t kMaxFunctions = 200000;
constexpr uint64_t kMaxCodeBytes = 64ull << 20;

struct Node {
    uint64_t low = 0;
    uint64_t high = 0;
    bool candidate = false;
    bool root = false;
    bool exported = false;
    bool address_taken = false;
    bool has_code = false;
    uint64_t file_offset = 0;
};

struct Ranges {
    std::vector<size_t> order;

    void build(const std::vector<Node>& nodes)
    {
        order.resize(nodes.size());
        for (size_t i = 0; i < nodes.size(); ++i)
            order[i] = i;
        std::sort(order.begin(), order.end(), [&](size_t a, size_t b) {
            if (nodes[a].low != nodes[b].low)
                return nodes[a].low < nodes[b].low;
            return a < b;
        });
    }

    std::optional<size_t> find(const std::vector<Node>& nodes,
                               uint64_t address) const
    {
        auto it = std::upper_bound(
            order.begin(), order.end(), address,
            [&](uint64_t value, size_t index) {
                return value < nodes[index].low;
            });
        if (it != order.begin()) {
            const size_t index = *(it - 1);
            const Node& node = nodes[index];
            if (node.high > node.low) {
                if (address >= node.low && address < node.high)
                    return index;
            } else if (address == node.low) {
                return index;
            }
        }
        return std::nullopt;
    }
};

struct ElfHandle {
    int fd = -1;
    Elf* elf = nullptr;

    ~ElfHandle()
    {
        if (elf)
            elf_end(elf);
        if (fd >= 0)
            close(fd);
    }
};

bool open_elf(const std::string& path, ElfHandle* handle)
{
    handle->fd = open(path.c_str(), O_RDONLY | O_CLOEXEC);
    if (handle->fd < 0)
        return false;
    handle->elf = elf_begin(handle->fd, ELF_C_READ, nullptr);
    return handle->elf != nullptr;
}

struct SectionName {
    size_t shstrndx = 0;
};

bool section_name(Elf* elf, size_t shstrndx, GElf_Shdr* shdr,
                  const char** name)
{
    *name = elf_strptr(elf, shstrndx, shdr->sh_name);
    return *name != nullptr;
}

std::vector<uint64_t> hex_tokens(const std::string& text)
{
    std::vector<uint64_t> values;
    for (size_t i = 0; i + 2 < text.size(); ++i) {
        if (text[i] != '0' || (text[i + 1] != 'x' && text[i + 1] != 'X'))
            continue;
        size_t j = i + 2;
        uint64_t value = 0;
        bool any = false;
        while (j < text.size() &&
               std::isxdigit(static_cast<unsigned char>(text[j]))) {
            const char c = text[j];
            const int digit = c >= '0' && c <= '9'
                                  ? c - '0'
                                  : (std::tolower(c) - 'a' + 10);
            value = value * 16 + static_cast<uint64_t>(digit);
            any = true;
            ++j;
        }
        if (any)
            values.push_back(value);
        i = j;
    }
    return values;
}

std::string first_word(const std::string& text)
{
    size_t start = 0;
    while (start < text.size() &&
           std::isspace(static_cast<unsigned char>(text[start])))
        ++start;
    size_t end = start;
    while (end < text.size() &&
           !std::isspace(static_cast<unsigned char>(text[end])))
        ++end;
    return text.substr(start, end - start);
}

#ifdef CALLGRAPH_HAVE_LIBOPCODES
int append_printf(void* stream, const char* format, ...)
{
    auto* out = static_cast<std::string*>(stream);
    char buffer[512];
    va_list args;
    va_start(args, format);
    const int n = vsnprintf(buffer, sizeof(buffer), format, args);
    va_end(args);
    if (n > 0)
        out->append(buffer,
                    std::min<size_t>(static_cast<size_t>(n),
                                     sizeof(buffer) - 1));
    return n;
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

bool is_unconditional_jump(const std::string& mnemonic)
{
    return mnemonic.rfind("jmp", 0) == 0;
}

bool is_conditional_jump(const std::string& mnemonic)
{
    return mnemonic.size() > 1 && mnemonic[0] == 'j' &&
           !is_unconditional_jump(mnemonic);
}

bool is_loop(const std::string& mnemonic)
{
    return mnemonic.rfind("loop", 0) == 0;
}

// Includes indirect forms.  Used only to avoid mistaking an operand for a
// function address; direct call edges are added separately.
bool is_control_transfer(const std::string& mnemonic)
{
    return mnemonic.rfind("call", 0) == 0 ||
           is_unconditional_jump(mnemonic) ||
           is_conditional_jump(mnemonic) || is_loop(mnemonic);
}
#endif

bool symbol_is_context_switch(const char* name)
{
    if (!name)
        return false;
    auto matches = [&](const char* base) {
        const size_t length = strlen(base);
        return strncmp(name, base, length) == 0 &&
               (name[length] == '\0' || name[length] == '@');
    };
    return matches("setcontext") || matches("swapcontext") ||
           matches("makecontext");
}

struct ElfFacts {
    std::vector<size_t> global_roots;
    std::vector<size_t> init_roots;
    std::vector<size_t> exports;
    size_t ifunc = 0;
    bool context_switch = false;
};

bool collect_elf_facts(ElfHandle& handle, std::vector<Node>& nodes,
                       const Ranges& ranges, ElfFacts* facts,
                       std::string* reason)
{
    Elf* elf = handle.elf;
    size_t shstrndx = 0;
    if (elf_getshdrstrndx(elf, &shstrndx) != 0) {
        *reason = "cannot read section names";
        return false;
    }

    GElf_Ehdr ehdr;
    if (!gelf_getehdr(elf, &ehdr)) {
        *reason = "cannot read ELF header";
        return false;
    }
    if (ehdr.e_machine != EM_X86_64) {
        *reason = "unsupported architecture";
        return false;
    }
    if (ehdr.e_entry != 0) {
        if (auto index = ranges.find(nodes, ehdr.e_entry))
            facts->global_roots.push_back(*index);
    }

    Elf_Scn* scn = nullptr;
    while ((scn = elf_nextscn(elf, scn)) != nullptr) {
        GElf_Shdr shdr;
        if (!gelf_getshdr(scn, &shdr))
            continue;
        const char* name = nullptr;
        if (!section_name(elf, shstrndx, &shdr, &name))
            continue;

        if (shdr.sh_type == SHT_INIT_ARRAY || shdr.sh_type == SHT_FINI_ARRAY) {
            Elf_Data* data = elf_getdata(scn, nullptr);
            if (data) {
                for (size_t offset = 0; offset + sizeof(uint64_t) <=
                                           data->d_size;
                     offset += sizeof(uint64_t)) {
                    uint64_t value = 0;
                    memcpy(&value,
                           static_cast<const char*>(data->d_buf) + offset,
                           sizeof(value));
                    if (auto index = ranges.find(nodes, value))
                        facts->init_roots.push_back(*index);
                }
            }
            continue;
        }

        if (shdr.sh_type == SHT_SYMTAB || shdr.sh_type == SHT_DYNSYM) {
            Elf_Data* symbols = elf_getdata(scn, nullptr);
            if (!symbols)
                continue;
            if (shdr.sh_link == 0 || shdr.sh_link >= SHN_LORESERVE)
                continue;
            Elf_Scn* strscn = elf_getscn(elf, shdr.sh_link);
            if (!strscn)
                continue;
            GElf_Shdr strshdr;
            if (!gelf_getshdr(strscn, &strshdr))
                continue;
            if (shdr.sh_entsize == 0)
                continue;
            const size_t count = shdr.sh_size / shdr.sh_entsize;
            for (size_t i = 1; i < count; ++i) {
                GElf_Sym sym;
                if (!gelf_getsym(symbols, static_cast<int>(i), &sym))
                    continue;
                const char* sym_name =
                    elf_strptr(elf, shdr.sh_link, sym.st_name);
                if (symbol_is_context_switch(sym_name))
                    facts->context_switch = true;
                if (ELF64_ST_TYPE(sym.st_info) == STT_GNU_IFUNC)
                    ++facts->ifunc;
                if (shdr.sh_type != SHT_DYNSYM ||
                    sym.st_shndx == SHN_UNDEF)
                    continue;
                const unsigned bind = ELF64_ST_BIND(sym.st_info);
                if (bind != STB_GLOBAL && bind != STB_WEAK)
                    continue;
                if (ELF64_ST_TYPE(sym.st_info) != STT_FUNC &&
                    ELF64_ST_TYPE(sym.st_info) != STT_NOTYPE)
                    continue;
                if (auto index = ranges.find(nodes, sym.st_value)) {
                    facts->exports.push_back(*index);
                    nodes[*index].exported = true;
                }
            }
            continue;
        }

        if (shdr.sh_type == SHT_RELA || shdr.sh_type == SHT_REL) {
            Elf_Data* data = elf_getdata(scn, nullptr);
            if (!data || shdr.sh_link == 0 || shdr.sh_link >= SHN_LORESERVE)
                continue;
            Elf_Scn* symscn = elf_getscn(elf, shdr.sh_link);
            GElf_Shdr symshdr;
            if (!symscn || !gelf_getshdr(symscn, &symshdr))
                continue;
            Elf_Data* symbols = elf_getdata(symscn, nullptr);
            if (!symbols)
                continue;

            const size_t count = shdr.sh_size / shdr.sh_entsize;
            for (size_t i = 0; i < count; ++i) {
                GElf_Rela rela;
                if (!gelf_getrela(data, static_cast<int>(i), &rela)) {
                    GElf_Rel rel;
                    if (!gelf_getrel(data, static_cast<int>(i), &rel))
                        continue;
                    rela.r_offset = rel.r_offset;
                    rela.r_info = rel.r_info;
                    rela.r_addend = 0;
                }
                const unsigned type = GELF_R_TYPE(rela.r_info);
                if (type == R_X86_64_IRELATIVE) {
                    ++facts->ifunc;
                    continue;
                }
                const size_t sym_index = GELF_R_SYM(rela.r_info);
                GElf_Sym sym = {};
                if (sym_index != 0 &&
                    !gelf_getsym(symbols, static_cast<int>(sym_index), &sym))
                    continue;

                uint64_t value = 0;
                if (type == R_X86_64_RELATIVE) {
                    value = static_cast<uint64_t>(rela.r_addend);
                } else if (type == R_X86_64_64 ||
                           type == R_X86_64_GLOB_DAT ||
                           type == R_X86_64_JUMP_SLOT) {
                    value = sym.st_value +
                            static_cast<uint64_t>(rela.r_addend);
                } else {
                    continue;
                }
                if (auto index = ranges.find(nodes, value))
                    nodes[*index].address_taken = true;
            }
            continue;
        }
    }
    return true;
}

bool collect_code_facts(const std::string& path,
                        const std::vector<FunctionInfo>& functions,
                        std::vector<Node>* nodes, const Ranges& ranges,
                        std::vector<std::vector<size_t>>* edges,
                        std::string* reason)
{
#ifdef CALLGRAPH_HAVE_LIBOPCODES
    int fd = open(path.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        *reason = "cannot open module";
        return false;
    }

    std::string text;
    struct disassemble_info dis;
    init_disassemble_info(&dis, &text, append_printf);
    dis.arch = bfd_arch_i386;
    dis.mach = bfd_mach_x86_64;
    dis.endian = BFD_ENDIAN_LITTLE;
    dis.read_memory_func = read_code;
    disassembler_ftype disassemble =
        disassembler(bfd_arch_i386, false, bfd_mach_x86_64, nullptr);
    if (!disassemble) {
        close(fd);
        *reason = "cannot create disassembler";
        return false;
    }

    for (size_t index = 0; index < functions.size(); ++index) {
        Node& node = (*nodes)[index];
        if (!node.has_code)
            continue;
        const uint64_t size = node.high - node.low;
        if (size == 0 || size > (16ull << 20)) {
            if (node.candidate) {
                close(fd);
                *reason = "function too large to analyze";
                return false;
            }
            continue;
        }
        std::vector<unsigned char> code(static_cast<size_t>(size));
        const ssize_t got = pread(fd, code.data(), code.size(),
                                  static_cast<off_t>(node.file_offset));
        if (got != static_cast<ssize_t>(code.size())) {
            close(fd);
            *reason = "cannot read function code";
            return false;
        }
        dis.buffer = code.data();
        dis.buffer_length = code.size();
        dis.buffer_vma = node.low;
        dis.stream = &text;

        bfd_vma pc = node.low;
        const bfd_vma end = node.low + code.size();
        while (pc < end) {
            text.clear();
            const int length = disassemble(pc, &dis);
            if (length <= 0) {
                close(fd);
                *reason = "cannot disassemble function";
                return false;
            }
            const std::string instruction = text;
            const std::string mnemonic = first_word(instruction);
            const bool is_call = mnemonic.rfind("call", 0) == 0;
            const bool is_jump = is_unconditional_jump(mnemonic);
            const bool is_control = is_control_transfer(mnemonic);
            const bool indirect = instruction.find('*') != std::string::npos;
            const auto tokens = hex_tokens(instruction);

            if ((is_call || is_jump) && !indirect && !tokens.empty()) {
                if (auto target = ranges.find(*nodes, tokens.front())) {
                    if (*target != index) {
                        // Direct edge; an excluded caller adds no depth.
                        (*edges)[index].push_back(*target);
                    }
                }
                // A direct call to a target outside this module has no
                // in-module edge.  Direct-call mode does not guess at
                // external or PLT targets.
            }

            // Any instruction operand that resolves into a known function
            // makes that function address-taken.  Branch targets are control
            // flow, not address-taking operands: skip the target of a direct
            // branch, and skip all operands of an indirect branch.
            size_t token_start = 0;
            if (is_control)
                token_start = (indirect || tokens.empty()) ? tokens.size() : 1;
            for (size_t t = token_start; t < tokens.size(); ++t) {
                if (auto target = ranges.find(*nodes, tokens[t]))
                    (*nodes)[*target].address_taken = true;
            }

            pc += static_cast<bfd_vma>(length);
        }
    }
    close(fd);
    return true;
#else
    (void)path;
    (void)functions;
    (void)nodes;
    (void)ranges;
    (void)edges;
    *reason = "libopcodes unavailable";
    return false;
#endif
}

void add_unique(std::vector<size_t>* values, size_t value)
{
    if (std::find(values->begin(), values->end(), value) == values->end())
        values->push_back(value);
}

StaticPruneResult unavailable(const std::string& reason)
{
    StaticPruneResult result;
    result.available = false;
    result.reason = reason;
    return result;
}

bool build_nodes(const StaticPruneRequest& request, std::vector<Node>* nodes,
                 Ranges* ranges, std::string* reason)
{
    if (!request.functions) {
        *reason = "no function table";
        return false;
    }
    if (request.functions->size() > kMaxFunctions) {
        *reason = "too many functions to analyze";
        return false;
    }

    nodes->clear();
    nodes->resize(request.functions->size());
    uint64_t total_code = 0;
    for (size_t i = 0; i < request.functions->size(); ++i) {
        const FunctionInfo& function = (*request.functions)[i];
        Node& node = (*nodes)[i];
        node.low = function.low_pc;
        node.high = function.high_pc;
        node.file_offset = function.file_offset;
        node.has_code = node.high > node.low;
        if (node.has_code)
            total_code += node.high - node.low;
    }
    if (total_code > kMaxCodeBytes) {
        *reason = "module code too large to analyze";
        return false;
    }

    for (const size_t index : request.candidates) {
        if (index >= nodes->size()) {
            *reason = "candidate index out of range";
            return false;
        }
        (*nodes)[index].candidate = true;
    }
    for (const size_t index : request.roots) {
        if (index >= nodes->size()) {
            *reason = "root index out of range";
            return false;
        }
        (*nodes)[index].root = true;
    }

    ranges->build(*nodes);
    return true;
}

StaticPruneResult compute_pruning(const StaticPruneRequest& request,
                                  bool use_code)
{
    if (request.trace_depth < 0)
        return unavailable("trace-depth is unlimited");

    std::vector<Node> nodes;
    Ranges ranges;
    std::string reason;
    if (!build_nodes(request, &nodes, &ranges, &reason))
        return unavailable(reason);

    // Explicit roots are always knowable without a call graph.
    if (request.has_root_scope) {
        StaticPruneResult result;
        result.available = true;
        for (const size_t root : request.roots) {
            if (nodes[root].candidate)
                result.keep.push_back(root);
        }
        result.roots_kept = result.keep.size();
        result.pruned = request.candidates.size() - result.keep.size();
        if (!use_code || request.trace_depth == 0)
            return result;
    } else if (request.attach_mode) {
        return unavailable("attach mode has dynamic roots");
    }

    if (request.is_go_binary)
        return unavailable("Go binaries use growable stacks");

    ElfHandle handle;
    if (!open_elf(request.module_path, &handle))
        return unavailable("cannot open module ELF");
    ElfFacts facts;
    if (!collect_elf_facts(handle, nodes, ranges, &facts, &reason))
        return unavailable(reason);
    if (facts.ifunc != 0)
        return unavailable("IFUNC targets are resolved at runtime");
    if (facts.context_switch)
        return unavailable("setcontext/swapcontext are not modeled");

    if (!use_code) {
        StaticPruneResult result;
        result.available = true;
        std::vector<size_t> roots = facts.global_roots;
        for (const size_t root : facts.init_roots)
            add_unique(&roots, root);
        for (const size_t root : facts.exports)
            add_unique(&roots, root);
        for (size_t i = 0; i < nodes.size(); ++i) {
            if (nodes[i].address_taken)
                add_unique(&roots, i);
        }
        for (const size_t root : roots) {
            if (nodes[root].candidate)
                add_unique(&result.keep, root);
        }
        std::sort(result.keep.begin(), result.keep.end());
        result.roots_kept = result.keep.size();
        result.pruned = request.candidates.size() - result.keep.size();
        return result;
    }

    std::vector<std::vector<size_t>> edges(nodes.size());
    if (!collect_code_facts(request.module_path, *request.functions, &nodes,
                            ranges, &edges, &reason))
        return unavailable(reason);

    std::vector<size_t> address_taken;
    for (size_t i = 0; i < nodes.size(); ++i) {
        if (nodes[i].exported || nodes[i].address_taken)
            add_unique(&address_taken, i);
    }

    std::vector<size_t> seeds;
    if (request.has_root_scope) {
        seeds = request.roots;
    } else {
        seeds = facts.global_roots;
        for (const size_t root : facts.init_roots)
            add_unique(&seeds, root);
        for (const size_t root : facts.exports)
            add_unique(&seeds, root);
        for (const size_t root : address_taken)
            add_unique(&seeds, root);
        // `main` is a conventional process entry even when its address is
        // materialised indirectly by libc rather than by a relocation.
        if (request.functions) {
            for (size_t i = 0; i < request.functions->size(); ++i) {
                if (nodes[i].candidate &&
                    (*request.functions)[i].name == "main")
                    add_unique(&seeds, i);
            }
        }
    }

    StaticPruneResult result;
    result.available = true;
    if (seeds.empty()) {
        result.reason = "no roots found";
        result.pruned = request.candidates.size();
        return result;
    }

    std::vector<uint64_t> dist(nodes.size(), kInf);
    std::deque<size_t> queue;
    for (const size_t seed : seeds) {
        if (seed >= nodes.size())
            continue;
        if (dist[seed] != 0) {
            dist[seed] = 0;
            queue.push_back(seed);
        }
    }

    const uint64_t limit = static_cast<uint64_t>(request.trace_depth);
    while (!queue.empty()) {
        const size_t u = queue.front();
        queue.pop_front();
        const uint64_t du = dist[u];
        if (du == kInf)
            continue;
        if (nodes[u].candidate && du >= limit)
            continue;

        const uint64_t cost = nodes[u].candidate ? 1 : 0;
        auto relax = [&](size_t v) {
            if (u == v || v >= nodes.size())
                return;
            const uint64_t nd = du + cost;
            if (nd < dist[v]) {
                dist[v] = nd;
                if (cost == 0)
                    queue.push_front(v);
                else
                    queue.push_back(v);
            }
        };

        for (const size_t v : edges[u])
            relax(v);
    }

    for (size_t i = 0; i < nodes.size(); ++i) {
        if (!nodes[i].candidate)
            continue;
        if (dist[i] <= limit && dist[i] != kInf)
            result.keep.push_back(i);
    }
    std::sort(result.keep.begin(), result.keep.end());
    result.roots_kept = 0;
    for (const size_t root : request.roots) {
        if (nodes[root].root && dist[root] != kInf)
            ++result.roots_kept;
    }
    result.pruned = request.candidates.size() - result.keep.size();
    return result;
}

}  // namespace

StaticPruneResult prune_statically(const StaticPruneRequest& request)
{
    if (!request.has_root_scope && request.attach_mode)
        return unavailable("attach mode has dynamic roots");
    return compute_pruning(request, true);
}

StaticPruneResult select_roots(const StaticPruneRequest& request)
{
    if (request.trace_depth != 0)
        return unavailable("root-only selection requires trace-depth 0");
    if (request.has_root_scope)
        return compute_pruning(request, false);
    if (request.attach_mode)
        return unavailable("attach mode has dynamic roots");

    // Prefer the full code scan when available: it finds code-materialised
    // roots such as main.  Fall back to ELF metadata when it is not.
    StaticPruneResult result = compute_pruning(request, true);
    if (!result.available)
        result = compute_pruning(request, false);
    if (result.available && request.functions) {
        for (size_t i = 0; i < request.functions->size(); ++i) {
            if ((*request.functions)[i].name != "main")
                continue;
            if (std::find(request.candidates.begin(),
                          request.candidates.end(), i) !=
                request.candidates.end())
                add_unique(&result.keep, i);
        }
        std::sort(result.keep.begin(), result.keep.end());
        result.pruned = request.candidates.size() - result.keep.size();
    }
    return result;
}

}  // namespace callgraph
