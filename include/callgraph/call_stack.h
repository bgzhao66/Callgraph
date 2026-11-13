#pragma once

#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

#include "callgraph/argument_info.h"
#include "callgraph/event.h"
#include "callgraph/latency_stats.h"
#include "callgraph/span.h"

namespace callgraph {

class Output;

struct CallFrame {
    uint64_t function_id;
    uint64_t start_ts;
    uint64_t span_token = 0;
    // User stack pointer at entry.  Zero when unknown (offline text traces).
    uint64_t sp = 0;
};

struct ThreadState {
    std::vector<CallFrame> frames;
};

// Reconstructs one logical call stack per TID from the event stream.
class CallStack {
public:
    CallStack(const std::vector<std::string>& names,
              const std::vector<FunctionSignature>* signatures, Output& output,
              int max_depth, bool verbose, bool collect_latency = false,
              SpanSink* sink = nullptr);

    CallStack(const std::vector<std::string>& names, Output& output,
              int max_depth, bool verbose, bool collect_latency = false,
              SpanSink* sink = nullptr);

    // Output may be null for offline span conversion.  The six-argument form
    // is unambiguous when nullptr is passed as the output.
    CallStack(const std::vector<std::string>& names,
              const std::vector<FunctionSignature>* signatures,
              Output* output, int max_depth, bool verbose,
              bool collect_latency, SpanSink* sink);

    CallStack(const std::vector<std::string>& names, Output* output,
              int max_depth, bool verbose, bool collect_latency = false,
              SpanSink* sink = nullptr);

    // Offline text traces carry an explicit depth column.  When it is present,
    // an entry at depth d closes any frames at depth >= d first, so a call at
    // the same depth as the current top is a sibling root rather than a child.
    // Live tracing passes -1 and derives depth from the stack.
    void on_event(const TraceEvent& event,
                  const std::string& arguments_override = {},
                  int depth_hint = -1);

    // The entry-rsp heuristic assumes one monotonically descending stack per
    // thread.  Runtimes that switch stacks (ucontext, Boost.Context, Go
    // goroutines) violate that, so they can disable it and fall back to
    // return matching.
    void set_rsp_resync(bool enabled) { rsp_resync_ = enabled; }

    // Marks frames still live at shutdown as incomplete.  Safe to call more
    // than once; only the first call has an effect.
    void finish_statistics();

    // Read-only view of the current frames for a thread, root-first.  The
    // pointer is valid only until the next CallStack mutation.  Returns null
    // when the thread has no traced frames.
    const std::vector<CallFrame>* frames_for(uint32_t tid) const;

    // Closes spans for frames that never returned.  Independent of
    // --histogram/collect_latency.
    void finish_spans(uint64_t stop_ts);

    const LatencyStats& stats() const { return stats_; }

    uint64_t entries() const { return entries_; }
    uint64_t returns() const { return returns_; }
    uint64_t desyncs() const { return desyncs_; }
    uint64_t stray_returns() const { return stray_returns_; }
    uint64_t bad_events() const { return bad_events_; }
    size_t live_threads() const { return threads_.size(); }

private:
    void emit_line(uint64_t ts, uint32_t tid, uint32_t depth, const char* arrow,
                   const std::string& name);

    // Closes frames [keep, frames.size()) from the top down, treating them as
    // calls that never returned.  Resizes the stack to keep.  Returns the
    // number of frames closed.
    size_t close_skipped_frames(uint32_t tid, std::vector<CallFrame>& frames,
                                size_t keep, uint64_t ts);

    const std::vector<std::string>& names_;
    const std::vector<FunctionSignature>* signatures_;
    Output* output_;
    int max_depth_;
    bool verbose_;
    bool collect_latency_;
    bool rsp_resync_ = true;
    SpanSink* sink_;
    bool stats_finished_ = false;
    bool spans_finished_ = false;

    std::unordered_map<uint32_t, ThreadState> threads_;
    LatencyStats stats_;

    uint64_t entries_ = 0;
    uint64_t returns_ = 0;
    uint64_t desyncs_ = 0;
    uint64_t stray_returns_ = 0;
    uint64_t bad_events_ = 0;
};

}  // namespace callgraph
