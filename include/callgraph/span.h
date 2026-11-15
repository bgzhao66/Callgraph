#pragma once

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

#include "callgraph/span_context.h"

namespace callgraph {

enum class SpanCloseReason {
    Return,
    Desync,
    Shutdown,
};

inline const char* span_close_reason_name(SpanCloseReason reason)
{
    switch (reason) {
    case SpanCloseReason::Return:
        return "return";
    case SpanCloseReason::Desync:
        return "desync";
    case SpanCloseReason::Shutdown:
        return "shutdown";
    }
    return "unknown";
}

enum class SpanAttributeType : uint8_t {
    String,
    Int,
    Double,
    Bool,
};

// An additional typed span attribute, used by kernel spans.  Function spans
// keep their fixed attribute set.
struct SpanAttribute {
    std::string key;
    SpanAttributeType type = SpanAttributeType::String;
    std::string string_value;
    int64_t int_value = 0;
    double double_value = 0.0;
    bool bool_value = false;
};

inline SpanAttribute make_span_string(std::string key, std::string value)
{
    SpanAttribute attribute;
    attribute.key = std::move(key);
    attribute.type = SpanAttributeType::String;
    attribute.string_value = std::move(value);
    return attribute;
}

inline SpanAttribute make_span_int(std::string key, int64_t value)
{
    SpanAttribute attribute;
    attribute.key = std::move(key);
    attribute.type = SpanAttributeType::Int;
    attribute.int_value = value;
    return attribute;
}

inline SpanAttribute make_span_double(std::string key, double value)
{
    SpanAttribute attribute;
    attribute.key = std::move(key);
    attribute.type = SpanAttributeType::Double;
    attribute.double_value = value;
    return attribute;
}

inline SpanAttribute make_span_bool(std::string key, bool value)
{
    SpanAttribute attribute;
    attribute.key = std::move(key);
    attribute.type = SpanAttributeType::Bool;
    attribute.bool_value = value;
    return attribute;
}

// Immutable per-function metadata used while constructing span attributes.
struct FunctionMetadata {
    std::string name;
    std::string linkage_name;
    std::string module_path;
    std::string module_build_id;
    std::string source_file;
    uint64_t file_offset = 0;
    uint32_t source_line = 0;
};

// A completed span, ready to be encoded on a different thread.
struct SpanRecord {
    SpanContext context;
    uint64_t function_id = 0;

    uint32_t tid = 0;
    uint32_t depth = 0;

    uint64_t start_unix_ns = 0;
    uint64_t end_unix_ns = 0;

    FunctionMetadata function;
    std::string thread_name;
    std::string arguments;
    // Kernel-derived spans use the function name as the span name and carry
    // typed attributes instead of source-code attributes.
    bool kernel = false;
    std::vector<SpanAttribute> extra_attributes;
    // Empirical quantile of this trace's duration, set on the root span when
    // outlier tail sampling is active.  Negative when unset.
    double quantile = -1.0;
    bool incomplete = false;
    SpanCloseReason reason = SpanCloseReason::Return;
};

// Receives semantic call events from CallStack.  Implementations must not
// block: build a SpanRecord and queue it for a writer thread instead.
class SpanSink {
public:
    virtual ~SpanSink() = default;

    // Returns an opaque token that CallStack stores in the frame and passes
    // back on exit.  The token is the span ID in the current implementation.
    virtual uint64_t on_function_enter(uint32_t tid, uint64_t function_id,
                                       uint32_t depth, uint64_t ts,
                                       const std::string& arguments,
                                       uint64_t parent_token) = 0;

    virtual void on_function_exit(uint32_t tid, uint64_t token,
                                  uint64_t function_id, uint64_t ts,
                                  SpanCloseReason reason) = 0;
};

}  // namespace callgraph
