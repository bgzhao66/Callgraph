#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace callgraph {

// One hardware counter request.  The type/config pair is passed directly to
// perf_event_open(); keeping the numbers opaque here lets callers link this
// header without the perf ABI.
struct PmuCounter {
    std::string name;
    uint32_t type = 0;
    uint64_t config = 0;
};

// A single counter value read from one thread.  enabled_ns/running_ns are the
// perf group or event totals; running_ns < enabled_ns means the counter was
// multiplexed and value is raw (unscaled).
struct PmuCountValue {
    uint64_t value = 0;
    uint64_t enabled_ns = 0;
    uint64_t running_ns = 0;
    bool valid = false;
};

struct PmuThreadCounts {
    uint32_t tid = 0;
    // True when the kernel-time part could not be measured and the event was
    // reopened with exclude_kernel.
    bool user_only = false;
    // Indexed by the counter list passed to format_pmu_counts().
    std::vector<PmuCountValue> values;
};

// One PERF_RECORD_SAMPLE delivered by the sampling collector.
struct PmuSample {
    uint64_t ts = 0;
    uint32_t tid = 0;
    uint32_t cpu = 0;
    uint64_t ip = 0;
    uint64_t period = 0;
    uint32_t event_index = 0;
    // True when the kernel did not provide a timestamp and receipt time was
    // used instead.
    bool timestamp_from_receipt = false;
};

// The counters enabled by --events pmu.
std::vector<PmuCounter> default_pmu_counters();

// Parses one name, alias, or r<hex> raw event.  Returns false and fills error
// on an unknown or malformed name.
bool parse_pmu_counter(const std::string& text, PmuCounter* out,
                       std::string* error);

// Parses a comma-separated counter list.  The output is appended to.
bool parse_pmu_counters(const std::string& list, std::vector<PmuCounter>* out,
                        std::string* error);

std::string supported_pmu_counters();

// Renders the shutdown count report.  Returns an empty string when no thread
// produced counts.
std::string format_pmu_counts(const std::vector<PmuCounter>& counters,
                              const std::vector<PmuThreadCounts>& threads);

// One-line --dry-run description of the requested PMU work.
std::string format_pmu_plan(const std::vector<PmuCounter>& counters,
                            bool sampling, uint64_t sampling_period,
                            int perf_event_paranoid);

// Reads /proc/sys/kernel/perf_event_paranoid, or -1 when unavailable.
int read_perf_event_paranoid();

}  // namespace callgraph
