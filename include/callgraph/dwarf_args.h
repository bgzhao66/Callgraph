#pragma once

#include <cstddef>
#include <string>
#include <vector>

#include "callgraph/function_info.h"

namespace callgraph {

// Fills FunctionInfo::signature from DWARF for every function whose address
// can be found in the debug information.  Returns the number of functions
// annotated.  External debug files (build-id / .gnu_debuglink) are found by
// libdwfl.
std::size_t annotate_parameters(const std::string& path,
                                std::vector<FunctionInfo>& functions);

}  // namespace callgraph
