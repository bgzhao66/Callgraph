#pragma once

#include <cstdint>
#include <functional>
#include <string>
#include <sys/types.h>
#include <unordered_map>
#include <vector>

#include "callgraph/clock_converter.h"
#include "callgraph/span.h"
#include "callgraph/span_context.h"

namespace callgraph {

enum class TraceScope {
    Root,
    Thread,
    Process,
};

bool parse_trace_scope(const std::string& text, TraceScope* scope);
const char* trace_scope_name(TraceScope scope);

struct SpanGeneratorConfig {
    TraceScope scope = TraceScope::Root;

    // Seed for trace IDs.  Set both words to a stable value for reproducible
    // tests; use random_seed() in normal operation.
    uint64_t seed_hi = 0;
    uint64_t seed_lo = 0;

    // Live tracing passes monotonic timestamps and a ClockConverter.  Offline
    // conversion passes Unix epoch timestamps directly.
    bool timestamps_are_unix = false;
    const ClockConverter* clock = nullptr;

    const std::vector<FunctionMetadata>* functions = nullptr;

    // 1.0 keeps every root trace.  Sampling is decided once per root/trace and
    // inherited by all descendants, so a retained root never has missing
    // children because of sampling.
    double sample_rate = 1.0;

    // Thread names are resolved from /proc/<pid>/task/<tid>/comm in live mode.
    pid_t pid = 0;
    bool read_thread_names = false;
};

class SpanGenerator : public SpanSink {
public:
    using Emit = std::function<void(SpanRecord&&)>;

    SpanGenerator(SpanGeneratorConfig config, Emit emit);

    uint64_t on_function_enter(uint32_t tid, uint64_t function_id, uint32_t depth,
                      uint64_t ts, const std::string& arguments,
                      uint64_t parent_token) override;

    void on_function_exit(uint32_t tid, uint64_t token, uint64_t function_id,
                  uint64_t ts, SpanCloseReason reason) override;

    uint64_t spans_closed() const { return spans_closed_; }
    uint64_t spans_sampled_out() const { return spans_sampled_out_; }

private:
    struct TraceInfo {
        TraceId trace_id{};
        bool sampled = true;
    };

    struct OpenSpan {
        SpanContext context;
        uint64_t function_id = 0;
        uint32_t tid = 0;
        uint32_t depth = 0;
        uint64_t start_ts = 0;
        bool sampled = true;
        std::string thread_name;
        std::string arguments;
    };

    TraceInfo new_trace(uint32_t tid, uint64_t sequence);
    TraceInfo trace_for_thread(uint32_t tid);
    TraceInfo trace_for_process();
    bool sample_root(uint32_t tid, uint64_t sequence) const;
    std::string thread_name(uint32_t tid);
    uint64_t to_unix(uint64_t ts) const;

    SpanGeneratorConfig config_;
    Emit emit_;
    SpanContextManager context_manager_;

    std::unordered_map<uint64_t, OpenSpan> open_;
    std::unordered_map<uint32_t, TraceInfo> thread_traces_;
    std::unordered_map<uint32_t, uint64_t> root_sequences_;
    std::unordered_map<uint32_t, std::string> thread_names_;
    TraceInfo process_trace_{};
    bool process_trace_initialized_ = false;
    uint64_t spans_closed_ = 0;
    uint64_t spans_sampled_out_ = 0;
};

}  // namespace callgraph
