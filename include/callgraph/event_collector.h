#pragma once

#include <cstdint>
#include <functional>
#include <sys/types.h>

struct ring_buffer;

namespace callgraph {

class CallStack;

class EventCollector {
public:
    EventCollector(int events_fd, CallStack& stack);
    ~EventCollector();

    EventCollector(const EventCollector&) = delete;
    EventCollector& operator=(const EventCollector&) = delete;

    // Polls until the target exits or a signal sets g_stop.  tick(), when
    // provided, runs on the collector thread between poll iterations and is
    // used to discover newly loaded modules.
    void run(pid_t target, pid_t child,
             const std::function<void()>& tick = {});

    uint64_t bad_events() const { return bad_events_; }

private:
    static int on_event(void* ctx, void* data, size_t size);

    int events_fd_;
    CallStack& stack_;
    ring_buffer* rb_ = nullptr;
    uint64_t bad_events_ = 0;
};

}  // namespace callgraph
