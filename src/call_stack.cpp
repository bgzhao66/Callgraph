#include "callgraph/call_stack.h"

#include <cstdio>

#include "callgraph/common.h"
#include "callgraph/output.h"

namespace callgraph {

CallStack::CallStack(const std::vector<std::string>& names,
                     const std::vector<FunctionSignature>* signatures,
                     Output& output, int max_depth, bool verbose)
    : names_(names), signatures_(signatures), output_(output),
      max_depth_(max_depth), verbose_(verbose)
{
}

CallStack::CallStack(const std::vector<std::string>& names, Output& output,
                     int max_depth, bool verbose)
    : CallStack(names, nullptr, output, max_depth, verbose)
{
}

void CallStack::on_event(const TraceEvent& event)
{
    if (event.func_id >= names_.size()) {
        ++bad_events_;
        return;
    }

    const std::string& name = names_[event.func_id];

    if (event.type == kEventEnter) {
        auto& state = threads_[event.tid];
        const uint32_t depth = static_cast<uint32_t>(state.frames.size());

        if (max_depth_ < 0 || depth <= static_cast<uint32_t>(max_depth_)) {
            std::string display = name;
            if (signatures_ && event.func_id < signatures_->size())
                display += format_arguments((*signatures_)[event.func_id],
                                            event);
            output_.emit(event.ts, event.tid, depth, "->", display);
        }

        state.frames.push_back({event.func_id, event.ts});
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

    if (index != frames.size()) {
        const size_t skipped = frames.size() - index;
        desyncs_ += skipped;
        if (verbose_) {
            log_verbose("tid %u: return of %s skipped %zu frame(s)", event.tid,
                        name.c_str(), skipped);
        }
    }

    if (max_depth_ < 0 || depth <= static_cast<uint32_t>(max_depth_))
        output_.emit(event.ts, event.tid, depth, "<-", name);

    frames.resize(index - 1);
    ++returns_;

    if (frames.empty())
        threads_.erase(it);
}

}  // namespace callgraph
