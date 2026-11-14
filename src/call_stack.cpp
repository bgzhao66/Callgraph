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

size_t CallStack::close_skipped_frames(uint32_t tid,
                                       std::vector<CallFrame>& frames,
                                       size_t keep, uint64_t ts)
{
    if (keep >= frames.size())
        return 0;
    const size_t skipped = frames.size() - keep;

    desyncs_ += skipped;
    if (sink_) {
        for (size_t i = frames.size(); i > keep; --i) {
            const CallFrame& frame = frames[i - 1];
            sink_->on_function_exit(tid, frame.span_token, frame.function_id,
                                    ts, SpanCloseReason::Desync);
        }
    }
    if (collect_latency_)
        stats_.mark_incomplete(tid, skipped);

    frames.resize(keep);
    return skipped;
}

void CallStack::on_event(const TraceEvent& event,
                         const std::string& arguments_override,
                         int depth_hint)
{
    if (event.func_id >= names_.size()) {
        ++bad_events_;
        return;
    }

    const std::string& name = names_[event.func_id];

    if (event.type == kEventEnter) {
        auto& state = threads_[event.tid];

        // Offline text traces carry the tracer's depth, which is more
        // authoritative than the reconstructed stack.  An entry at depth d
        // cannot be nested under a frame at depth >= d: those frames either
        // returned without a matching exit line or belong to another branch.
        // Examples are pq_getmsgstring() followed by pg_client_to_server()
        // at depth 0: the second call is a new root, not a callee of the
        // first.
        if (depth_hint >= 0 &&
            static_cast<size_t>(depth_hint) < state.frames.size()) {
            const size_t unwound = close_skipped_frames(
                event.tid, state.frames, static_cast<size_t>(depth_hint),
                event.ts);
            if (unwound != 0 && verbose_) {
                log_verbose("tid %u: entry of %s at depth %d closed %zu "
                            "frame(s)",
                            event.tid, name.c_str(), depth_hint, unwound);
            }
        }

        // A callee's entry rsp is strictly below its caller's, so a recorded
        // frame at or above this rsp cannot be an ancestor: it was unwound by
        // longjmp/exception/tail call, or its return event was lost.  Offline
        // traces have no rsp (zero) and keep the old behaviour.  Stackful
        // runtimes switch to unrelated stacks, where the ordering does not
        // hold, so they can turn this off with --no-rsp-resync.
        if (rsp_resync_ && event.sp != 0) {
            size_t keep = state.frames.size();
            while (keep > 0 && state.frames[keep - 1].sp != 0 &&
                   state.frames[keep - 1].sp <= event.sp)
                --keep;

            const size_t unwound =
                close_skipped_frames(event.tid, state.frames, keep, event.ts);
            if (unwound != 0 && verbose_) {
                log_verbose("tid %u: entry of %s at sp 0x%llx unwound %zu "
                            "frame(s)",
                            event.tid, name.c_str(),
                            static_cast<unsigned long long>(event.sp), unwound);
            }
        }

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

        state.frames.push_back(
            {event.func_id, event.ts, span_token, event.sp});
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

    // Copy the returning frame: closing the frames above it resizes the stack.
    const CallFrame frame = frames[index - 1];

    // Frames above the match never returned.  Close their spans with the
    // timestamp of the event that revealed the gap, then close the match.
    const size_t skipped =
        close_skipped_frames(event.tid, frames, index, event.ts);
    if (skipped != 0 && verbose_) {
        log_verbose("tid %u: return of %s skipped %zu frame(s)", event.tid,
                    name.c_str(), skipped);
    }

    if (max_depth_ < 0 || depth <= static_cast<uint32_t>(max_depth_))
        emit_line(event.ts, event.tid, depth, "<-", name);

    if (collect_latency_) {
        const uint64_t duration =
            event.ts >= frame.start_ts ? event.ts - frame.start_ts : 0;
        // close_skipped_frames() already trimmed the stack to the matched
        // frame, so frames[0..index) is the full root-to-callee path.
        path_scratch_.clear();
        path_scratch_.reserve(index);
        for (size_t i = 0; i < index; ++i)
            path_scratch_.push_back(frames[i].function_id);
        stats_.record(event.tid, path_scratch_, duration);
    }

    if (sink_) {
        sink_->on_function_exit(event.tid, frame.span_token, frame.function_id,
                        event.ts, SpanCloseReason::Return);
    }

    frames.pop_back();
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

const std::vector<CallFrame>* CallStack::frames_for(uint32_t tid) const
{
    const auto it = threads_.find(tid);
    return it == threads_.end() ? nullptr : &it->second.frames;
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
