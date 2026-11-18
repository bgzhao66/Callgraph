#include "callgraph/call_stack.h"

#include <cstdio>
#include <algorithm>

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

bool CallStack::ingest_root(uint32_t tid)
{
    if (ingest_sample_rate_ >= 1.0)
        return true;
    if (ingest_sample_rate_ <= 0.0)
        return false;

    const uint64_t sequence = ingest_sequences_[tid]++;
    const uint64_t value =
        splitmix64(0x9e3779b97f4a7c15ULL ^
                   (static_cast<uint64_t>(tid) << 32) ^
                   (sequence * 0xbf58476d1ce4e5b9ULL));
    const uint64_t threshold =
        static_cast<uint64_t>(ingest_sample_rate_ * 1000000.0);
    return (value % 1000000ULL) < threshold;
}

size_t CallStack::close_skipped_frames(uint32_t tid,
                                       std::vector<CallFrame>& frames,
                                       size_t keep, uint64_t ts)
{
    if (keep >= frames.size())
        return 0;
    const size_t skipped = frames.size() - keep;

    desyncs_ += skipped;
    uint64_t traced_skipped = 0;
    if (sink_) {
        for (size_t i = frames.size(); i > keep; --i) {
            const CallFrame& frame = frames[i - 1];
            if (!frame.traced)
                continue;
            ++traced_skipped;
            sink_->on_function_exit(tid, frame.span_token, frame.function_id,
                                    ts, SpanCloseReason::Desync);
        }
    } else {
        for (size_t i = keep; i < frames.size(); ++i) {
            if (frames[i].traced)
                ++traced_skipped;
        }
    }
    if (collect_latency_)
        stats_.mark_incomplete(tid, traced_skipped);

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
            if (unwound != 0) {
                state.hidden_depth = 0;
                if (verbose_) {
                    log_verbose("tid %u: entry of %s at depth %d closed %zu "
                                "frame(s)",
                                event.tid, name.c_str(), depth_hint, unwound);
                }
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
            if (unwound != 0) {
                state.hidden_depth = 0;
                if (verbose_) {
                    log_verbose("tid %u: entry of %s at sp 0x%llx unwound %zu "
                                "frame(s)",
                                event.tid, name.c_str(),
                                static_cast<unsigned long long>(event.sp),
                                unwound);
                }
            }
        }

        const uint32_t absolute_depth =
            static_cast<uint32_t>(state.frames.size());

        // A resync may have unwound the active root.
        if (state.root_active && state.frames.size() <= state.root_index) {
            state.root_active = false;
            state.root_index = 0;
            state.hidden_depth = 0;
        }

        const bool activates_root =
            !state.root_active &&
            (!has_root_scope_ ||
             (trace_roots_ && trace_roots_->count(event.func_id) != 0));

        if (!state.root_active && !activates_root) {
            // Pre-root ancestor: kept only so returns pair correctly.  It never
            // produces text, spans, or histogram entries.
            state.frames.push_back(
                {event.func_id, event.ts, 0, event.sp, false, false});
            ++entries_;
            return;
        }

        if (activates_root) {
            state.root_active = true;
            state.root_index = absolute_depth;
            state.hidden_depth = 0;
        }

        const uint32_t depth =
            absolute_depth - static_cast<uint32_t>(state.root_index);

        // --trace-depth: stop reconstructing user frames below the cut.
        // Their entries are still counted so the matching returns can be
        // consumed without disturbing the retained stack.
        if (trace_depth_ >= 0 &&
            depth > static_cast<uint32_t>(trace_depth_)) {
            ++state.hidden_depth;
            return;
        }
        // A retained entry means the stream has returned to the traced part
        // of the stack, so any hidden frames were already closed (or lost).
        if (state.hidden_depth != 0)
            state.hidden_depth = 0;

        bool traced = true;
        bool logged = true;
        if (activates_root) {
            traced = ingest_root(event.tid);
            logged = traced;
            if (!traced)
                ++ingest_skipped_roots_;
        } else {
            traced = state.frames.back().traced;
            logged = state.frames.back().logged;
        }

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

        if (logged &&
            (max_depth_ < 0 || depth <= static_cast<uint32_t>(max_depth_)))
            emit_line(event.ts, event.tid, depth, "->", display);

        const uint64_t parent_token =
            activates_root || state.frames.empty()
                ? 0
                : state.frames.back().span_token;
        uint64_t span_token = 0;
        if (sink_ && traced) {
            span_token = sink_->on_function_enter(event.tid, event.func_id, depth,
                                         event.ts, arguments, parent_token);
        }

        state.frames.push_back(
            {event.func_id, event.ts, span_token, event.sp, traced, logged});
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

    auto& state = it->second;
    auto& frames = state.frames;

    if (state.hidden_depth != 0) {
        // Offline traces carry the authoritative depth, so a return at a
        // retained depth means the hidden subtree was unwound after all.
        if (depth_hint >= 0 && trace_depth_ >= 0 &&
            depth_hint <= trace_depth_) {
            state.hidden_depth = 0;
        } else {
            --state.hidden_depth;
            return;
        }
    }

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

    const size_t absolute_index = index - 1;
    const bool within_root =
        state.root_active && absolute_index >= state.root_index;
    const bool is_root =
        within_root && absolute_index == state.root_index;
    const uint32_t depth =
        within_root
            ? static_cast<uint32_t>(absolute_index - state.root_index)
            : 0;

    // Copy the returning frame: closing the frames above it resizes the stack.
    const CallFrame frame = frames[absolute_index];

    // Frames above the match never returned.  Close their spans with the
    // timestamp of the event that revealed the gap, then close the match.
    const size_t skipped =
        close_skipped_frames(event.tid, frames, index, event.ts);
    if (skipped != 0 && verbose_) {
        log_verbose("tid %u: return of %s skipped %zu frame(s)", event.tid,
                    name.c_str(), skipped);
    }

    // A skipped return may have unwound the active root.
    if (state.root_active && frames.size() <= state.root_index) {
        state.root_active = false;
        state.root_index = 0;
        state.hidden_depth = 0;
    }

    if (within_root) {
        if (frame.logged &&
            (max_depth_ < 0 || depth <= static_cast<uint32_t>(max_depth_)))
            emit_line(event.ts, event.tid, depth, "<-", name);

        if (collect_latency_) {
            const uint64_t duration =
                event.ts >= frame.start_ts ? event.ts - frame.start_ts : 0;
            // The path starts at the active root, not at pre-root ancestors.
            path_scratch_.clear();
            path_scratch_.reserve(index - state.root_index);
            for (size_t i = state.root_index; i < index; ++i)
                path_scratch_.push_back(frames[i].function_id);
            stats_.record(event.tid, path_scratch_, duration);
        }

        if (sink_ && frame.traced) {
            sink_->on_function_exit(event.tid, frame.span_token,
                                    frame.function_id, event.ts,
                                    SpanCloseReason::Return);
        }
    }

    frames.pop_back();
    ++returns_;

    if (is_root ||
        (state.root_active && frames.size() <= state.root_index)) {
        state.root_active = false;
        state.root_index = 0;
        state.hidden_depth = 0;
    }

    if (frames.empty())
        threads_.erase(it);
}

void CallStack::finish_statistics()
{
    if (!collect_latency_ || stats_finished_)
        return;
    stats_finished_ = true;

    for (const auto& [tid, state] : threads_) {
        if (!state.root_active)
            continue;
        const size_t live = state.frames.size() - state.root_index;
        if (live == 0)
            continue;

        stats_.mark_incomplete(tid, live);

        std::vector<uint64_t> stack;
        stack.reserve(live);
        for (size_t i = state.root_index; i < state.frames.size(); ++i)
            stack.push_back(state.frames[i].function_id);
        stats_.mark_live(tid, stack);
    }
}

std::span<const CallFrame> CallStack::traced_frames_for(uint32_t tid) const
{
    const auto it = threads_.find(tid);
    if (it == threads_.end() || !it->second.root_active)
        return {};
    const auto& frames = it->second.frames;
    const size_t start = std::min(it->second.root_index, frames.size());
    return std::span<const CallFrame>(frames.data() + start,
                                      frames.size() - start);
}

void CallStack::finish_spans(uint64_t stop_ts)
{
    if (!sink_ || spans_finished_)
        return;
    spans_finished_ = true;

    for (const auto& [tid, state] : threads_) {
        for (auto it = state.frames.rbegin(); it != state.frames.rend(); ++it) {
            if (!it->traced)
                continue;
            sink_->on_function_exit(tid, it->span_token, it->function_id, stop_ts,
                            SpanCloseReason::Shutdown);
        }
    }
}

}  // namespace callgraph
