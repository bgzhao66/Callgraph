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
                    size_t indent_step = 0);
    ~Output();

    Output(const Output&) = delete;
    Output& operator=(const Output&) = delete;

    void emit(uint64_t ts, uint32_t tid, uint32_t depth,
              const char* arrow, const std::string& name);
    void stop();

    uint64_t dropped() const { return dropped_.load(std::memory_order_relaxed); }

private:
    void worker();
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

    static constexpr size_t kMaxQueuedBytes = 64ull << 20;
};

}  // namespace callgraph
