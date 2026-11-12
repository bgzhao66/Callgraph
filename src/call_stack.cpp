#include "callgraph/call_stack.h"

#include <cstdio>

#include "callgraph/common.h"
#include "callgraph/output.h"

namespace callgraph {

CallStack::CallStack(const std::vector<std::string>& names,
                     const std::vector<FunctionSignature>* signatures,
                     Output& output, int max_depth, bool verbose,
                     bool collect_latency, SpanSink* sink)
    : CallStack(names, signatures, &output, max_depth, verbose,
                collect_latency, sink)
{
}

CallStack::CallStack(const std::vector<std::string>& names, Output& output,
                     int max_depth, bool verbose, bool collect_latency,
                     SpanSink* sink)
    : CallStack(names, nullptr, &output, max_depth, verbose, collect_latency,
                sink)
{
}

CallStack::CallStack(const std::vector<std::string>& names,
                     const std::vector<FunctionSignature>* signatures,
                     Output* output, int max_depth, bool verbose,
                     bool collect_latency, SpanSink* sink)
    : names_(names), signatures_(signatures), output_(output),
      max_depth_(max_depth), verbose_(verbose),
      collect_latency_(collect_latency), sink_(sink)
{
}

CallStack::CallStack(const std::vector<std::string>& names, Output* output,
                     int max_depth, bool verbose, bool collect_latency,
                     SpanSink* sink)
    : CallStack(names, nullptr, output, max_depth, verbose, collect_latency,
                sink)
{
}

void CallStack::emit_line(uint64_t ts, uint32_t tid, uint32_t depth,
                          const char* arrow, const std::string& name)
{
    if (output_)
        output_->emit(ts, tid, depth, arrow, name);
}

void CallStack::on_event(const TraceEvent& event,
                         const std::string& arguments_override)
{
    if (event.func_id >= names_.size()) {
        ++bad_events_;
        return;
    }

    const std::string& name = names_[event.func_id];

    if (event.type == kEventEnter) {
        auto& state = threads_[event.tid];
        const uint32_t depth = static_cast<uint32_t>(state.frames.size());

        std::string arguments = arguments_override;
        if (arguments.empty() && signatures_ &&
            event.func_id < signatures_->size()) {
            arguments = format_arguments((*signatures_)[event.func_id], event);
        }
        if (!arguments.empty() && arguments.front() == ' ')
            arguments.erase(0, 1);

        std::string display = name;
        if (!arguments.empty())
            display += " " + arguments;

        if (max_depth_ < 0 || depth <= static_cast<uint32_t>(max_depth_))
            emit_line(event.ts, event.tid, depth, "->", display);

        const uint64_t parent_token =
            state.frames.empty() ? 0 : state.frames.back().span_token;
        uint64_t span_token = 0;
        if (sink_) {
            span_token = sink_->on_function_enter(event.tid, event.func_id, depth,
                                         event.ts, arguments, parent_token);
        }

        state.frames.push_back({event.func_id, event.ts, span_token});
        ++entries_;
        return;
    }

    if (event.type != kEventExit) {
        ++bad_events_;
        return;
    }

    auto it = threads_.find(event.tid);
    if (it == threads_.end()) {
        ++stray_returns_;
        return;
    }

    auto& frames = it->second.frames;

    // Normally the returning function is on top.  If it is not, a frame was
    // skipped (longjmp, exception unwinding, tail call, lost event).  Search
    // down the stack for the matching invocation instead of corrupting it.
    size_t index = frames.size();
    while (index > 0 && frames[index - 1].function_id != event.func_id)
        --index;

    if (index == 0) {
        ++stray_returns_;
        return;
    }

    const uint32_t depth = static_cast<uint32_t>(index - 1);

    // Frames above the match never returned.  Close their spans with the
    // timestamp of the event that revealed the gap, then close the match.
    const size_t skipped = frames.size() - index;
    if (skipped != 0) {
        desyncs_ += skipped;
        if (verbose_) {
            log_verbose("tid %u: return of %s skipped %zu frame(s)", event.tid,
                        name.c_str(), skipped);
        }
        if (sink_) {
            for (size_t i = frames.size(); i > index; --i) {
                const CallFrame& skipped_frame = frames[i - 1];
                sink_->on_function_exit(event.tid, skipped_frame.span_token,
                                skipped_frame.function_id, event.ts,
                                SpanCloseReason::Desync);
            }
        }
        if (collect_latency_)
            stats_.mark_incomplete(event.tid, skipped);
    }

    if (max_depth_ < 0 || depth <= static_cast<uint32_t>(max_depth_))
        emit_line(event.ts, event.tid, depth, "<-", name);

    if (collect_latency_) {
        const CallFrame& frame = frames[index - 1];
        const uint64_t parent =
            index >= 2 ? frames[index - 2].function_id : kRootFunction;
        const uint64_t duration =
            event.ts >= frame.start_ts ? event.ts - frame.start_ts : 0;
        stats_.record(event.tid, parent, frame.function_id, duration);
    }

    if (sink_) {
        const CallFrame& frame = frames[index - 1];
        sink_->on_function_exit(event.tid, frame.span_token, frame.function_id,
                        event.ts, SpanCloseReason::Return);
    }

    frames.resize(index - 1);
    ++returns_;

    if (frames.empty())
        threads_.erase(it);
}

void CallStack::finish_statistics()
{
    if (!collect_latency_ || stats_finished_)
        return;
    stats_finished_ = true;

    for (const auto& [tid, state] : threads_) {
        stats_.mark_incomplete(tid, state.frames.size());

        if (state.frames.empty())
            continue;

        std::vector<uint64_t> live;
        live.reserve(state.frames.size());
        for (const auto& frame : state.frames)
            live.push_back(frame.function_id);
        stats_.mark_live(tid, live);
    }
}

void CallStack::finish_spans(uint64_t stop_ts)
{
    if (!sink_ || spans_finished_)
        return;
    spans_finished_ = true;

    for (const auto& [tid, state] : threads_) {
        for (auto it = state.frames.rbegin(); it != state.frames.rend(); ++it) {
            sink_->on_function_exit(tid, it->span_token, it->function_id, stop_ts,
                            SpanCloseReason::Shutdown);
        }
    }
}

}  // namespace callgraph
