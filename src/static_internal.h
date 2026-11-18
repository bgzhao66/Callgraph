// SPDX-License-Identifier: AGPL-3.0-only
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "callgraph/function_info.h"
#include "callgraph/static_call_graph.h"

namespace callgraph {
namespace internal {

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

    void build(const std::vector<Node>& nodes);
    std::optional<size_t> find(const std::vector<Node>& nodes,
                               uint64_t address) const;
};

struct ElfFacts {
    std::vector<size_t> global_roots;
    std::vector<size_t> init_roots;
    std::vector<size_t> exports;
    size_t ifunc = 0;
    bool context_switch = false;
};

void add_unique(std::vector<size_t>* values, size_t value);
StaticPruneResult unavailable(const std::string& reason);

bool build_nodes(const StaticPruneRequest& request, std::vector<Node>* nodes,
                 Ranges* ranges, std::string* reason);

// Opens `path` and fills ELF-level facts, marking exported nodes.
bool collect_elf_facts(const std::string& path, std::vector<Node>& nodes,
                       const Ranges& ranges, ElfFacts* facts,
                       std::string* reason);

// Direct-code facts (libopcodes).  Only the disassembler-enabled build
// installs a collector; the tracer leaves it null and consumes JSON facts.
using CodeFactsCollector =
    bool (*)(const std::string& path,
             const std::vector<FunctionInfo>& functions,
             std::vector<Node>* nodes, const Ranges& ranges,
             std::vector<std::vector<size_t>>* edges, bool keep_self_edges,
             std::string* reason);

void set_code_facts_collector(CodeFactsCollector collector);

}  // namespace internal
}  // namespace callgraph
