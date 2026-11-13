#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <sys/types.h>

#include "callgraph/event.h"
#include "callgraph/kernel_event.h"

struct ring_buffer;

namespace callgraph {

class CallStack;
class KernelTimeline;

class EventCollector {
public:
    EventCollector(int events_fd, CallStack& stack,
                   int kernel_events_fd = -1,
                   KernelTimeline* timeline = nullptr,
                   uint64_t merge_window_ns = 1000000,
                   std::function<void(uint32_t)> new_target_tid = {});
    ~EventCollector();

    EventCollector(const EventCollector&) = delete;
    EventCollector& operator=(const EventCollector&) = delete;

    // Polls until the target exits or a signal sets g_stop.  tick(), when
    // provided, runs on the collector thread between poll iterations and is
    // used to discover newly loaded modules and target threads.
    void run(pid_t target, pid_t child,
             const std::function<void()>& tick = {});

    uint64_t bad_events() const { return bad_events_; }
    uint64_t bad_kernel_events() const { return bad_kernel_events_; }
    uint64_t kernel_events_seen() const { return kernel_events_seen_; }

private:
    struct Pending {
        enum class Source { Function, Kernel };
        Source source;
        TraceEvent function = {};
        struct cg_kernel_event kernel = {};
    };

    static int on_event(void* ctx, void* data, size_t size);
    static int on_kernel_event(void* ctx, void* data, size_t size);
    void enqueue(Pending event, uint64_t ts);
    void flush(uint64_t watermark, bool all);
    void process(Pending& pending);
    void process_function(const TraceEvent& event);
    void process_kernel(const struct cg_kernel_event& event);

    int events_fd_;
    int kernel_events_fd_;
    CallStack& stack_;
    KernelTimeline* timeline_;
    uint64_t merge_window_ns_;
    std::function<void(uint32_t)> new_target_tid_;
    ring_buffer* rb_ = nullptr;
    std::multimap<uint64_t, Pending> pending_;
    uint64_t max_ts_ = 0;
    bool merge_mode_ = false;
    uint64_t bad_events_ = 0;
    uint64_t bad_kernel_events_ = 0;
    uint64_t kernel_events_seen_ = 0;
};

}  // namespace callgraph
