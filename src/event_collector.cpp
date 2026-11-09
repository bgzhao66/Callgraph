#include "callgraph/event_collector.h"

#include <bpf/libbpf.h>
#include <cerrno>
#include <csignal>
#include <cstring>
#include <poll.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

#include "callgraph/call_stack.h"
#include "callgraph/common.h"
#include "callgraph/process_controller.h"
#include "trace.h"

namespace callgraph {

extern volatile sig_atomic_t g_stop;

EventCollector::EventCollector(int events_fd, CallStack& stack)
    : events_fd_(events_fd), stack_(stack)
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
    self->stack_.on_event(*static_cast<const TraceEvent*>(data));
    return 0;
}

void EventCollector::run(pid_t target, pid_t child,
                         const std::function<void()>& tick)
{
    rb_ = ring_buffer__new(events_fd_, on_event, this, nullptr);
    if (!rb_)
        fail("cannot create ring buffer: %s", errno_string(errno).c_str());

    int pidfd = -1;
    if (child <= 0)
        pidfd = static_cast<int>(syscall(SYS_pidfd_open, target, 0));

    while (!g_stop) {
        const int n = ring_buffer__poll(rb_, 100);
        if (n < 0 && n != -EINTR) {
            log_warn("ring buffer poll failed: %s",
                     errno_string(-n).c_str());
            break;
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

    if (pidfd >= 0)
        close(pidfd);
}

}  // namespace callgraph
