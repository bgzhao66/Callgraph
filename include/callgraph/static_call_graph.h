#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "callgraph/function_info.h"

namespace callgraph {

// External call-graph facts for one module, re-indexed into the consumer's
// `functions` table.  Produced by callgraph-disasm and joined by low_pc.
struct StaticGraphFacts {
    // Direct `call`/unconditional `jmp` targets per function index.
    std::vector<std::vector<size_t>> edges;
    // Conventional root metadata, per function index.
    std::vector<size_t> entry;
    std::vector<size_t> init;
    std::vector<size_t> exports;
    std::vector<size_t> address_taken;
    // File offsets of `ret` instructions per function index.
    std::vector<std::vector<uint64_t>> return_offsets;
    bool has_returns = false;
    // False when the graph itself is unreliable.  `prune_reason` says why.
    bool prunable = true;
    std::string prune_reason;

    bool valid() const { return !edges.empty(); }
};

// Input for direct-call probe pruning.  All indices refer to `functions`.
struct StaticPruneRequest {
    std::string module_path;
    const std::vector<FunctionInfo>* functions = nullptr;
    // Functions that survive --exclude.  Only these may be instrumented.
    std::vector<size_t> candidates;
    // Functions matching --root-scope and not excluded.
    std::vector<size_t> roots;
    bool has_root_scope = false;
    int trace_depth = -1;
    bool attach_mode = false;
    bool is_go_binary = false;
    bool verbose = false;
    // External facts from callgraph-disasm.  When null the built-in
    // disassembler (if this build has one) is used instead.
    const StaticGraphFacts* facts = nullptr;
};

struct StaticPruneResult {
    // False when the call graph cannot be built reliably.  Callers must not
    // treat `keep` as complete in that case.
    bool available = false;
    std::string reason;
    // Indices into `functions`, always a subset of `candidates`.
    std::vector<size_t> keep;
    size_t pruned = 0;
    size_t roots_kept = 0;
};

// Direct-call call-graph pruning for --trace-depth N > 0.  Indirect call
// sites add no targets; omit --trace-depth to instrument every non-excluded
// function instead.
StaticPruneResult prune_statically(const StaticPruneRequest& request);

// Root-only selection for --trace-depth 0.  This uses ELF entry/init/exported/
// address-taken metadata and does not require a disassembler.
StaticPruneResult select_roots(const StaticPruneRequest& request);

// Conventional roots for a module: ELF entry, init/fini array entries,
// dynamic exports, address-taken functions, and `main`.  `main` sorts first;
// everything else ascends by address.
std::vector<size_t> static_graph_roots(
    const std::vector<FunctionInfo>& functions,
    const std::vector<size_t>& entry, const std::vector<size_t>& init,
    const std::vector<size_t>& exports,
    const std::vector<size_t>& address_taken);

}  // namespace callgraph
