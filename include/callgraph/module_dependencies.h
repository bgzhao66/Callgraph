#pragma once

#include <string>
#include <vector>

namespace callgraph {

// Resolves `path` plus its transitive DT_NEEDED closure using the module's
// PT_INTERP (or the host loader for shared objects).  `modules` receives the
// input first, then the dependencies in loader order.  linux-vdso and the
// dynamic loader itself are not included.
bool module_dependencies(const std::string& path,
                         std::vector<std::string>* modules,
                         std::string* reason);

}  // namespace callgraph
