#pragma once

#include <array>
#include <cstdint>

namespace callgraph {

using TraceId = std::array<uint8_t, 16>;

struct SpanContext {
    TraceId trace_id{};
    uint64_t span_id = 0;
    uint64_t parent_span_id = 0;
};

// Generates OTLP-compatible trace and span identifiers.
class SpanContextManager {
public:
    SpanContextManager(uint64_t seed_hi, uint64_t seed_lo);

    TraceId new_trace(uint32_t tid, uint64_t sequence);
    uint64_t next_span_id();

private:
    uint64_t seed_hi_;
    uint64_t seed_lo_;
    uint64_t next_span_id_ = 1;
};

// Generates a non-zero random 128-bit seed.
void random_seed(uint64_t* hi, uint64_t* lo);

}  // namespace callgraph
