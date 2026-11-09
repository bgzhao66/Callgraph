#pragma once

#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

#include "callgraph/event.h"

namespace callgraph {

class Output;

struct CallFrame {
    uint64_t function_id;
    uint64_t start_ts;
};

struct ThreadState {
    std::vector<CallFrame> frames;
};

// Reconstructs one logical call stack per TID from the event stream.
class CallStack {
public:
    CallStack(const std::vector<std::string>& names, Output& output,
              int max_depth, bool verbose);

    void on_event(const TraceEvent& event);

    uint64_t entries() const { return entries_; }
    uint64_t returns() const { return returns_; }
    uint64_t desyncs() const { return desyncs_; }
    uint64_t stray_returns() const { return stray_returns_; }
    uint64_t bad_events() const { return bad_events_; }
    size_t live_threads() const { return threads_.size(); }

private:
    const std::vector<std::string>& names_;
    Output& output_;
    int max_depth_;
    bool verbose_;

    std::unordered_map<uint32_t, ThreadState> threads_;

    uint64_t entries_ = 0;
    uint64_t returns_ = 0;
    uint64_t desyncs_ = 0;
    uint64_t stray_returns_ = 0;
    uint64_t bad_events_ = 0;
};

}  // namespace callgraph
