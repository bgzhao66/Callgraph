// SPDX-License-Identifier: AGPL-3.0-only
#pragma once

#include <string>
#include <vector>

#include "callgraph/function_info.h"
#include "callgraph/static_call_graph.h"
#include "callgraph/static_graph_json.h"

namespace callgraph {

// Finds the module in `document` that describes `build_id` (preferred) or
// `path`.  Returns null when neither matches.
const StaticGraphModule* find_static_graph_module(
    const StaticGraphDocument& document, const std::string& build_id,
    const std::string& path);

// Re-indexes one module's facts into the consumer's `functions` table by
// low_pc.  Returns false when no function matched, so callers can distinguish
// "facts for a different build" from "facts with no returns".
bool join_static_graph_module(const StaticGraphModule& module,
                              const std::vector<FunctionInfo>& functions,
                              StaticGraphFacts* facts);

// Copies joined return offsets into `functions` so ret-mode probes can be
// attached.  Returns the number of functions that received offsets.
size_t apply_static_graph_returns(const StaticGraphFacts& facts,
                                  std::vector<FunctionInfo>* functions);

// Conventional roots for one facts module, using the same policy as the
// tracer: entry, init/fini, exports, address-taken, then `main`.
std::vector<size_t> static_graph_module_roots(const StaticGraphModule& module);

}  // namespace callgraph
