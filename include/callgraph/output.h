#pragma once

#include <atomic>
#include <condition_variable>
#include <cstdio>
#include <deque>
#include <mutex>
#include <string>
#include <thread>

namespace callgraph {

// Serializes complete event lines onto one output stream.
//
// A dedicated writer thread decouples the ring-buffer consumer from stdout
// backpressure.  If the queue grows beyond its budget, lines are dropped and
// counted rather than blocking the collector.
class Output {
public:
    explicit Output(const std::string& path);
    ~Output();

    Output(const Output&) = delete;
    Output& operator=(const Output&) = delete;

    void emit(uint64_t ts, uint32_t tid, uint32_t depth,
              const char* arrow, const std::string& name);
    void stop();

    uint64_t dropped() const { return dropped_.load(std::memory_order_relaxed); }

private:
    void worker();

    FILE* fp_ = nullptr;
    bool own_fp_ = false;

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
