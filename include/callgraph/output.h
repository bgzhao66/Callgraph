#pragma once

#include <atomic>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <deque>
#include <mutex>
#include <string>
#include <thread>

namespace callgraph {

class ClockConverter;

enum class TimestampMode {
    BootSeconds,  // seconds since boot, CLOCK_MONOTONIC
    WallClock,    // local wall clock, ISO 8601
};

// Serializes complete event lines onto one output stream.
//
// A dedicated writer thread decouples the ring-buffer consumer from stdout
// backpressure.  If the queue grows beyond its budget, lines are dropped and
// counted rather than blocking the collector.
class Output {
public:
    explicit Output(const std::string& path,
                    TimestampMode mode = TimestampMode::BootSeconds,
                    size_t indent_step = 0,
                    const ClockConverter* clock = nullptr);
    ~Output();

    Output(const Output&) = delete;
    Output& operator=(const Output&) = delete;

    void emit(uint64_t ts, uint32_t tid, uint32_t depth,
              const char* arrow, const std::string& name);
    void emit_kernel(uint64_t ts, uint32_t tid, int depth,
                     const char* category, const std::string& event,
                     const std::string& attributes = {});

    // Limits stdout user lines and kernel lines independently.  Each stream
    // gets its own token bucket at this rate; zero disables the limit.
    // Suppressed lines are counted but not queued.
    void set_log_rate_limit(uint64_t lines_per_second);

    struct RateLimitReport {
        uint64_t user = 0;
        uint64_t kernel = 0;
        uint64_t total() const { return user + kernel; }
    };

    uint64_t user_lines_suppressed() const
    {
        return user_lines_suppressed_;
    }
    uint64_t kernel_lines_suppressed() const
    {
        return kernel_lines_suppressed_;
    }
    uint64_t lines_suppressed() const
    {
        return user_lines_suppressed_ + kernel_lines_suppressed_;
    }

    // Returns the suppressions since the previous call and resets the delta.
    RateLimitReport take_rate_limit_report();

    void stop();
    // Stops the writer and appends a trailer (for example the histogram
    // report) directly to the stream, after every queued event line.
    void finish(const std::string& trailer = {});

    uint64_t dropped() const { return dropped_.load(std::memory_order_relaxed); }
    uint64_t dropped_kernel() const
    {
        return dropped_kernel_.load(std::memory_order_relaxed);
    }

private:
    struct RateBucket {
        uint64_t rate = 0;
        double tokens = 0.0;
        uint64_t last_ts = 0;
        bool started = false;
    };

    bool log_allowed(RateBucket& bucket, uint64_t ts);
    void worker();
    void enqueue_line(std::string line, bool kernel);
    std::string format_timestamp(uint64_t ts_ns) const;

    FILE* fp_ = nullptr;
    bool own_fp_ = false;

    TimestampMode mode_;
    int64_t wall_offset_ns_ = 0;
    size_t indent_step_ = 0;

    std::mutex mu_;
    std::condition_variable cv_;
    std::deque<std::string> queue_;
    size_t queued_bytes_ = 0;
    bool stop_ = false;

    std::thread thread_;
    std::atomic<uint64_t> dropped_{0};
    std::atomic<uint64_t> dropped_kernel_{0};

    // The limiter is called from the collector thread only.  The counters are
    // read from that thread (periodic reports) or after it stops (summary).
    RateBucket user_rate_;
    RateBucket kernel_rate_;
    uint64_t user_lines_suppressed_ = 0;
    uint64_t kernel_lines_suppressed_ = 0;
    uint64_t reported_user_lines_ = 0;
    uint64_t reported_kernel_lines_ = 0;

    static constexpr size_t kMaxQueuedBytes = 64ull << 20;
};

}  // namespace callgraph
