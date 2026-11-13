#include "callgraph/event_collector.h"

#include <bpf/libbpf.h>
#include <algorithm>
#include <cerrno>
#include <csignal>
#include <cstring>
#include <poll.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#include "callgraph/call_stack.h"
#include "callgraph/common.h"
#include "callgraph/kernel_timeline.h"
#include "callgraph/process_controller.h"
#include "trace.h"

namespace callgraph {

extern volatile sig_atomic_t g_stop;

EventCollector::EventCollector(int events_fd, CallStack& stack,
                               int kernel_events_fd,
                               KernelTimeline* timeline,
                               uint64_t merge_window_ns,
                               std::function<void(uint32_t)> new_target_tid)
    : events_fd_(events_fd), kernel_events_fd_(kernel_events_fd),
      stack_(stack), timeline_(timeline), merge_window_ns_(merge_window_ns),
      new_target_tid_(std::move(new_target_tid))
{
}

EventCollector::~EventCollector()
{
    if (rb_)
        ring_buffer__free(rb_);
}

int EventCollector::on_event(void* ctx, void* data, size_t size)
{
    auto* self = static_cast<EventCollector*>(ctx);
    if (size < sizeof(TraceEvent)) {
        ++self->bad_events_;
        return 0;
    }
    const TraceEvent& event = *static_cast<const TraceEvent*>(data);
    if (self->new_target_tid_)
        self->new_target_tid_(event.tid);
    if (self->merge_mode_) {
        Pending pending;
        pending.source = Pending::Source::Function;
        pending.function = event;
        self->enqueue(std::move(pending), event.ts);
    } else {
        self->process_function(event);
    }
    return 0;
}

int EventCollector::on_kernel_event(void* ctx, void* data, size_t size)
{
    auto* self = static_cast<EventCollector*>(ctx);
    if (size < sizeof(cg_kernel_event)) {
        ++self->bad_kernel_events_;
        return 0;
    }
    const cg_kernel_event& event = *static_cast<const cg_kernel_event*>(data);
    self->kernel_events_seen_ += 1;
    Pending pending;
    pending.source = Pending::Source::Kernel;
    pending.kernel = event;
    self->enqueue(std::move(pending), event.ts);
    return 0;
}

void EventCollector::enqueue(Pending event, uint64_t ts)
{
    max_ts_ = std::max(max_ts_, ts);
    pending_.emplace(ts, std::move(event));
}

void EventCollector::process_function(const TraceEvent& event)
{
    if (timeline_)
        timeline_->on_function_event(event, stack_);
    stack_.on_event(event);
}

void EventCollector::process_kernel(const cg_kernel_event& event)
{
    if (timeline_)
        timeline_->on_kernel_event(event, stack_);
}

void EventCollector::process(Pending& pending)
{
    if (pending.source == Pending::Source::Function)
        process_function(pending.function);
    else
        process_kernel(pending.kernel);
}

void EventCollector::flush(uint64_t watermark, bool all)
{
    while (!pending_.empty()) {
        auto it = pending_.begin();
        if (!all && it->first > watermark)
            break;
        Pending pending = std::move(it->second);
        pending_.erase(it);
        process(pending);
    }
}

void EventCollector::run(pid_t target, pid_t child,
                         const std::function<void()>& tick)
{
    merge_mode_ = timeline_ != nullptr && kernel_events_fd_ >= 0;
    rb_ = ring_buffer__new(events_fd_, on_event, this, nullptr);
    if (!rb_)
        fail("cannot create ring buffer: %s", errno_string(errno).c_str());

    if (kernel_events_fd_ >= 0) {
        const int err =
            ring_buffer__add(rb_, kernel_events_fd_, on_kernel_event, this);
        if (err != 0)
            fail("cannot add kernel ring buffer: %s",
                 errno_string(-err).c_str());
    }

    int pidfd = -1;
    if (child <= 0)
        pidfd = static_cast<int>(syscall(SYS_pidfd_open, target, 0));

    while (!g_stop) {
        const int n = ring_buffer__poll(rb_, 20);
        if (n < 0 && n != -EINTR) {
            log_warn("ring buffer poll failed: %s",
                     errno_string(-n).c_str());
            break;
        }

        if (merge_mode_) {
            if (n == 0) {
                flush(max_ts_, true);
            } else {
                const uint64_t watermark =
                    max_ts_ > merge_window_ns_ ? max_ts_ - merge_window_ns_ : 0;
                flush(watermark, false);
            }
        }

        if (tick)
            tick();

        if (child > 0) {
            int status = 0;
            const pid_t reaped = waitpid(child, &status, WNOHANG);
            if (reaped == child)
                break;
            if (reaped < 0 && errno == ECHILD)
                break;
        } else if (pidfd >= 0) {
            struct pollfd pfd = {pidfd, POLLIN, 0};
            if (poll(&pfd, 1, 0) > 0)
                break;
        } else if (!ProcessController::alive(target)) {
            break;
        }
    }

    // Drain events that were already committed to the ring buffer.
    while (ring_buffer__consume(rb_) > 0) {
    }
    if (merge_mode_)
        flush(max_ts_, true);

    if (pidfd >= 0)
        close(pidfd);
}

}  // namespace callgraph
