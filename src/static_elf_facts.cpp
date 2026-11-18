// SPDX-License-Identifier: AGPL-3.0-only
#include "static_internal.h"

#include <elf.h>
#include <fcntl.h>
#include <gelf.h>
#include <libelf.h>
#include <unistd.h>

#include <algorithm>
#include <cstring>
#include <optional>
#include <string>
#include <vector>

namespace callgraph {
namespace internal {
namespace {

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

bool section_name(Elf* elf, size_t shstrndx, GElf_Shdr* shdr,
                  const char** name)
{
    *name = elf_strptr(elf, shstrndx, shdr->sh_name);
    return *name != nullptr;
}

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

}  // namespace

void Ranges::build(const std::vector<Node>& nodes)
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

std::optional<size_t> Ranges::find(const std::vector<Node>& nodes,
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

bool collect_elf_facts(const std::string& path, std::vector<Node>& nodes,
                       const Ranges& ranges, ElfFacts* facts,
                       std::string* reason)
{
    ElfHandle handle;
    if (!open_elf(path, &handle)) {
        *reason = "cannot open module ELF";
        return false;
    }

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
                for (size_t offset = 0;
                     offset + sizeof(uint64_t) <= data->d_size;
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
                if (shdr.sh_type != SHT_DYNSYM || sym.st_shndx == SHN_UNDEF)
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

}  // namespace internal
}  // namespace callgraph
