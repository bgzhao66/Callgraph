#pragma once

#include <iosfwd>
#include <string>

#include "callgraph/static_graph_json.h"

namespace callgraph {

// Renders one module's roots as a Unicode tree, expanding every call path.
// Cycles are cut with " [recursive]"; no line is shared between branches.
// Writes incrementally so an exponential expansion does not buffer in memory.
void write_static_graph(const StaticGraphModule& module, std::ostream& out);

// Convenience wrapper used by tests and small modules.
std::string render_static_graph(const StaticGraphModule& module);

}  // namespace callgraph
