#pragma once

#include <cstddef>
#include <string>
#include <vector>

#include "callgraph/function_info.h"

namespace callgraph {

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

// Request for an offline direct-call graph (`export --static`).
struct StaticCallGraphRequest {
    std::string module_path;
    const std::vector<FunctionInfo>* functions = nullptr;
    // Explicit roots (indices into `functions`).  Used only when
    // `has_root_scope` is true; otherwise the conventional roots are used.
    std::vector<size_t> roots;
    bool has_root_scope = false;
};

struct StaticCallGraph {
    // False when the module cannot be analyzed (no libopcodes, not x86-64,
    // unreadable code, ...).  `reason` explains why.
    bool available = false;
    std::string reason;
    // Indices into `functions`, sorted by address with `main` first.
    std::vector<size_t> roots;
    // Direct `call`/unconditional `jmp` targets indexed by function index.
    // Self-calls are kept so direct recursion is visible.
    std::vector<std::vector<size_t>> edges;
};

// Builds a fully expanded direct-call graph.  Indirect calls, PLT/external
// calls, IFUNC targets, and cross-module calls are not followed.
StaticCallGraph build_static_call_graph(const StaticCallGraphRequest& request);

}  // namespace callgraph
