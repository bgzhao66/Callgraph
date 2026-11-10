#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "callgraph/event.h"

namespace callgraph {

// How a parameter value should be decoded for display.
enum class ArgumentKind {
    Integer,
    Unsigned,
    Pointer,
    Boolean,
    Char,
    Float,
    Aggregate,
    Unknown,
};

struct ParameterInfo {
    std::string name;
    std::string type_name;

    ArgumentKind kind = ArgumentKind::Unknown;
    uint32_t byte_size = 0;
    bool is_signed = false;
    bool artificial = false;      // e.g. C++ `this`
    bool contains_float = false;  // aggregate containing floating-point fields

    // Filled in by classify_parameters() using the x86-64 SysV ABI.
    bool in_sse = false;
    bool on_stack = false;
    bool unavailable = false;
    uint8_t gp_index = 0xff;
    uint8_t sse_index = 0xff;
    uint32_t stack_offset = 0;
};

struct FunctionSignature {
    std::vector<ParameterInfo> parameters;
    bool has_signature = false;
};

// Assigns GP/SSE/stack locations to parameters.  Safe to call repeatedly.
void classify_parameters(FunctionSignature& signature);

// Renders the argument suffix, for example " [x=3, p=0x7ffd...]".
// Returns an empty string when the signature has no displayable parameters.
std::string format_arguments(const FunctionSignature& signature,
                             const cg_event& event);

}  // namespace callgraph
