// SPDX-License-Identifier: GPL-3.0-only
#pragma once

#include <string>
#include <vector>

#include "callgraph/function_info.h"
#include "callgraph/static_graph_json.h"

namespace callgraph {

struct StaticGraphBuildRequest {
    std::string path;
    std::string build_id;
    // Function table from ElfResolver.  Return offsets are filled in place.
    std::vector<FunctionInfo>* functions = nullptr;
};

// Builds one module's facts with libopcodes.  Returns false and fills
// `reason` when the module cannot be analysed reliably (wrong architecture,
// unreadable code, IFUNC targets, stackful context switches, ...).
bool build_static_graph_module(const StaticGraphBuildRequest& request,
                               StaticGraphModule* module, std::string* reason);

}  // namespace callgraph
