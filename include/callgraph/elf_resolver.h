#pragma once

#include <string>
#include <vector>

#include "callgraph/function_info.h"

namespace callgraph {

struct ModuleInfo {
    std::string path;
    std::string build_id;
    bool has_exception_tables = false;
    // Go binaries have growable, relocatable goroutine stacks and a runtime
    // that validates return PCs, so tracing them needs special care.
    bool is_go_binary = false;
    std::vector<FunctionInfo> functions;
};

struct ResolveOptions {
    // Populate FunctionInfo::source_file/source_line from DWARF.
    bool annotate_source = true;
};

class ElfResolver {
public:
    // Resolves callable function entry points and names from the ELF file.
    // Throws Error when the file has no usable symbol table.
    static ModuleInfo resolve(const std::string& path,
                              const ResolveOptions& options = ResolveOptions{});
};

}  // namespace callgraph
