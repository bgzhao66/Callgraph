#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "callgraph/argument_info.h"

namespace callgraph {

struct FunctionInfo {
    uint64_t function_id = 0;

    std::string name;          // demangled display name
    std::string linkage_name;  // mangled symbol name

    uint64_t low_pc = 0;
    uint64_t high_pc = 0;
    uint64_t file_offset = 0;

    // File offsets of return instructions inside this function.  Only filled
    // when libopcodes is available and --return-mode=ret is usable.
    std::vector<uint64_t> return_offsets;

    std::string module_path;
    std::string module_build_id;
    std::string source_file;
    uint32_t source_line = 0;

    // Parameter metadata from DWARF, filled when --show-args is enabled.
    FunctionSignature signature;
};

}  // namespace callgraph
