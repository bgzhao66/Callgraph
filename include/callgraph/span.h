#pragma once

#include <cstdint>
#include <string>

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
