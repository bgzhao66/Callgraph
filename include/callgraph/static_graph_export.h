#pragma once

#include <iosfwd>
#include <string>
#include <vector>

#include "callgraph/function_info.h"
#include "callgraph/static_call_graph.h"

namespace callgraph {

struct StaticGraphView {
    const StaticCallGraph* graph = nullptr;
    const std::vector<FunctionInfo>* functions = nullptr;
};

// Renders one module's roots as a Unicode tree, expanding every call path.
// Cycles are cut with " [recursive]"; no line is shared between branches.
// Writes incrementally so an exponential expansion does not buffer in memory.
void write_static_graph(const StaticGraphView& view, std::ostream& out);

// Convenience wrapper used by tests and small modules.
std::string render_static_graph(const StaticGraphView& view);

}  // namespace callgraph
