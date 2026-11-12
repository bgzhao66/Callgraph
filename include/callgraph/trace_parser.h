#pragma once

#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

#include "callgraph/span.h"

namespace callgraph {

class CallStack;
struct TraceMetadata;

struct TraceParseOptions {
    bool input_show_args = false;
    bool have_monotonic_offset = false;
    uint64_t monotonic_offset_ns = 0;
};

struct TraceParseStats {
    uint64_t event_lines = 0;
    uint64_t ignored_lines = 0;
    uint64_t bad_lines = 0;
    uint64_t entries = 0;
    uint64_t exits = 0;
};

// Converts a callgraph text trace into synthetic TraceEvents and feeds them to
// CallStack.  Names and function metadata vectors grow as new names are seen;
// pointers to the vectors remain stable, so they may be passed to CallStack and
// SpanGenerator before parsing starts.
TraceParseStats parse_text_trace(
    const std::string& path, CallStack& stack, std::vector<std::string>& names,
    std::vector<FunctionMetadata>& functions,
    const TraceMetadata* metadata, const TraceParseOptions& options,
    uint64_t* last_ts);

}  // namespace callgraph
