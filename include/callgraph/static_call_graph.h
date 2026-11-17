#pragma once

#include <cstddef>
#include <string>
#include <vector>

#include "callgraph/function_info.h"

namespace callgraph {

// Input for conservative probe pruning.  All indices refer to `functions`.
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
    bool conservative = false;
};

// Full conservative call-graph pruning for --trace-depth N > 0.
StaticPruneResult prune_statically(const StaticPruneRequest& request);

// Root-only selection for --trace-depth 0.  This uses ELF entry/init/exported/
// address-taken metadata and does not require a disassembler.
StaticPruneResult select_roots(const StaticPruneRequest& request);

}  // namespace callgraph
