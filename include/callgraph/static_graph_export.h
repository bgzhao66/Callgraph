#pragma once

#include <iosfwd>
#include <string>

#include "callgraph/static_graph_json.h"

namespace callgraph {

// Renders one module's roots as a Unicode tree.  A function's subtree is
// expanded at most once per module; later occurrences end with " [...]".
// Cycles are cut with " [recursive]".  Root sections are separated by one
// blank line.  Writes incrementally so output does not buffer in memory.
void write_static_graph(const StaticGraphModule& module, std::ostream& out);

// Convenience wrapper used by tests and small modules.
std::string render_static_graph(const StaticGraphModule& module);

}  // namespace callgraph
