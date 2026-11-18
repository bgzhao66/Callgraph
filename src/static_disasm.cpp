// SPDX-License-Identifier: GPL-3.0-only
#include "callgraph/static_graph_build.h"

#include <fcntl.h>
#include <unistd.h>

#include <dis-asm.h>

#include <algorithm>
#include <cctype>
#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <string>
#include <utility>
#include <vector>

#include "callgraph/static_call_graph.h"
#include "static_internal.h"

namespace callgraph {
namespace {

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
bool scan_return_offsets(const std::string& path,
                         std::vector<FunctionInfo>* functions,
                         std::string* reason)
{
    int fd = open(path.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        *reason = "cannot open module";
        return false;
    }

    struct disassemble_info dis;
    init_disassemble_info(&dis, nullptr, discard_printf);
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

    for (FunctionInfo& info : *functions) {
        if (info.high_pc <= info.low_pc)
            continue;
        const uint64_t size = info.high_pc - info.low_pc;
        if (size > (16u << 20))
            continue;

        std::vector<unsigned char> code(static_cast<size_t>(size));
        const ssize_t got =
            pread(fd, code.data(), code.size(), info.file_offset);
        if (got <= 0)
            continue;
        code.resize(static_cast<size_t>(got));

        dis.buffer = code.data();
        dis.buffer_length = code.size();
        dis.buffer_vma = info.low_pc;

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

    close(fd);
    return true;
}

bool collect_code_facts(const std::string& path,
                        const std::vector<FunctionInfo>& functions,
                        std::vector<internal::Node>* nodes,
                        const internal::Ranges& ranges,
                        std::vector<std::vector<size_t>>* edges,
                        bool keep_self_edges, std::string* reason)
{
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
        internal::Node& node = (*nodes)[index];
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
                    if (*target != index || keep_self_edges) {
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
}

}  // namespace

bool build_static_graph_module(const StaticGraphBuildRequest& request,
                               StaticGraphModule* module, std::string* reason)
{
    if (!request.functions || request.functions->empty()) {
        *reason = "no function table";
        return false;
    }

    StaticPruneRequest prune;
    prune.module_path = request.path;
    prune.functions = request.functions;
    prune.trace_depth = 0;
    prune.candidates.resize(request.functions->size());
    for (size_t i = 0; i < prune.candidates.size(); ++i)
        prune.candidates[i] = i;

    std::vector<internal::Node> nodes;
    internal::Ranges ranges;
    if (!internal::build_nodes(prune, &nodes, &ranges, reason))
        return false;

    internal::ElfFacts facts;
    if (!internal::collect_elf_facts(request.path, nodes, ranges, &facts,
                                     reason))
        return false;

    std::string prune_reason;
    if (facts.ifunc != 0)
        prune_reason = "IFUNC targets are resolved at runtime";
    else if (facts.context_switch)
        prune_reason = "setcontext/swapcontext are not modeled";

    std::vector<std::vector<size_t>> edges(nodes.size());
    // A non-prunable module still needs return offsets, but its direct edges
    // are discarded by every consumer.  Skip the expensive code scan.
    if (prune_reason.empty()) {
        if (!collect_code_facts(request.path, *request.functions, &nodes,
                                ranges, &edges, true, reason))
            return false;
    }

    // One rendered edge per callee: repeated calls to the same function are
    // the same tree child.
    for (auto& callees : edges) {
        std::vector<size_t> unique;
        unique.reserve(callees.size());
        for (const size_t callee : callees) {
            if (std::find(unique.begin(), unique.end(), callee) == unique.end())
                unique.push_back(callee);
        }
        callees = std::move(unique);
    }

    if (!scan_return_offsets(request.path, request.functions, reason))
        return false;

    std::vector<size_t> address_taken;
    for (size_t i = 0; i < nodes.size(); ++i) {
        if (nodes[i].address_taken)
            address_taken.push_back(i);
    }

    module->path = request.path;
    module->build_id = request.build_id;
    module->arch = "x86_64";
    module->is_64bit = true;
    module->prunable = prune_reason.empty();
    module->prune_reason = std::move(prune_reason);
    module->functions.clear();
    module->functions.reserve(nodes.size());
    for (size_t i = 0; i < nodes.size(); ++i) {
        StaticGraphFunction function;
        function.name = (*request.functions)[i].name;
        function.linkage_name = (*request.functions)[i].linkage_name;
        function.low_pc = nodes[i].low;
        function.high_pc = nodes[i].high;
        function.file_offset = nodes[i].file_offset;
        function.has_code = nodes[i].has_code;
        function.exported = nodes[i].exported;
        function.address_taken = nodes[i].address_taken;
        function.return_offsets = (*request.functions)[i].return_offsets;
        module->functions.push_back(std::move(function));
    }
    for (const size_t index : facts.global_roots) {
        if (index < module->functions.size())
            module->functions[index].entry = true;
    }
    for (const size_t index : facts.init_roots) {
        if (index < module->functions.size())
            module->functions[index].init = true;
    }

    module->edges = std::move(edges);
    module->roots = static_graph_roots(*request.functions, facts.global_roots,
                                       facts.init_roots, facts.exports,
                                       address_taken);
    return true;
}

}  // namespace callgraph
