#pragma once

#include <string>
#include <vector>

#include "callgraph/function_info.h"

namespace callgraph {

struct ModuleInfo {
    std::string path;
    std::string build_id;
    bool has_exception_tables = false;
    std::vector<FunctionInfo> functions;
};

class ElfResolver {
public:
    // Resolves callable function entry points and names from the ELF file.
    // Throws Error when the file has no usable symbol table.
    static ModuleInfo resolve(const std::string& path);
};

}  // namespace callgraph
