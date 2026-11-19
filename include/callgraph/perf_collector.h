#pragma once

#include <sys/types.h>

#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>
#include <unordered_map>
#include <vector>

#include "callgraph/pmu.h"

namespace callgraph {

// Owns the per-thread perf events used by --pmu.  Counting opens one group
// per thread; sampling opens one event per counter per thread and mmaps a
// ring for each.  The collector is independent of the kernel BPF object.
class PerfCollector {
public:
    PerfCollector(pid_t target, std::vector<PmuCounter> counters,
                  bool sampling, uint64_t sampling_period, bool require,
                  bool verbose);
    ~PerfCollector();

    PerfCollector(const PerfCollector&) = delete;
    PerfCollector& operator=(const PerfCollector&) = delete;

    // Opens events for the threads that exist now.  Call after the target is
    // detached so enabled_ns excludes the ptrace stop window.
    void start();
    // Disables, reads, unmaps, and closes every event.  Idempotent.
    void stop();

    void refresh_tids();
    void add_target_tid(uint32_t tid);

    bool sampling() const { return sampling_; }
    bool has_fds() const { return !fds_.empty(); }
    const std::vector<int>& fds() const { return fds_; }

    // Reads every sampling ring and invokes on_sample for each record.
    void drain(const std::function<void(const PmuSample&)>& on_sample);

    std::string format_counts() const;

    uint64_t samples() const { return samples_; }
    uint64_t lost() const { return lost_; }
    size_t counter_count() const { return counters_.size(); }
    size_t thread_count() const { return threads_.size(); }
    bool unavailable() const { return unavailable_; }
    const std::string& error() const { return error_; }

private:
    struct Ring {
        int fd = -1;
        size_t counter_index = 0;
        void* base = nullptr;
        size_t data_size = 0;
        size_t map_size = 0;
    };

    struct ThreadEvents {
        uint32_t tid = 0;
        bool user_only = false;
        int leader_fd = -1;
        std::vector<int> fds;
        std::vector<size_t> counter_indices;
        std::vector<Ring> rings;
        std::vector<PmuCountValue> counts;
    };

    bool open_thread(uint32_t tid);
    bool open_counting_group(ThreadEvents& events);
    bool open_sampling_events(ThreadEvents& events);
    int open_event(uint32_t tid, const PmuCounter& counter, int group_fd,
                   bool sampling, bool user_only, bool* used_user_only,
                   std::string* error);
    bool map_ring(Ring* ring, std::string* error);
    void drain_ring(Ring& ring,
                    const std::function<void(const PmuSample&)>& on_sample);
    void read_counts();
    void close_thread(ThreadEvents& events);
    void rebuild_fd_list();
    void scan_tids(std::vector<uint32_t>* tids) const;

    pid_t target_;
    std::vector<PmuCounter> counters_;
    bool sampling_;
    uint64_t sampling_period_;
    bool require_;
    bool verbose_;
    bool started_ = false;
    bool initial_scan_ = false;
    bool unavailable_ = false;
    int last_errno_ = 0;
    std::string error_;
    std::unordered_map<uint32_t, ThreadEvents> threads_;
    std::vector<int> fds_;
    std::vector<PmuThreadCounts> counts_;
    uint64_t samples_ = 0;
    uint64_t lost_ = 0;
};

// Exposed for unit tests.  Both functions expect one complete perf record,
// including its perf_event_header.
bool parse_perf_sample(const char* data, size_t size, uint32_t counter_index,
                       uint64_t receipt_ns, PmuSample* sample);
bool parse_perf_lost(const char* data, size_t size, uint64_t* lost);

}  // namespace callgraph
