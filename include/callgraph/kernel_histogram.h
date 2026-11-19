#pragma once

#include <cstdint>
#include <map>
#include <string>
#include <unordered_map>

#include "callgraph/latency_stats.h"

namespace callgraph {

// Latency samples for one kernel event under one owning user call path.
struct KernelHistogram {
    LatencyHistogram histogram;
    // True when at least one sample was cut short: an unmatched syscall exit,
    // an interval still open at shutdown, or a scheduler interval that began
    // before the thread state was known.
    bool incomplete = false;
};

// Per owning user call path (root-first), then per kernel event label.
// Keying by the full path keeps different roots and call sites separate, so
// kernel samples stay with the user stack that produced them.
using KernelEventHistograms =
    std::unordered_map<CallPath, std::map<std::string, KernelHistogram>,
                       CallPathHash>;

// PMU samples are counts, not durations.  One entry per owning user call path
// and counter name.
struct PmuHistogram {
    uint64_t samples = 0;
    uint64_t events = 0;
};

using PmuHistograms =
    std::unordered_map<CallPath, std::map<std::string, PmuHistogram>,
                       CallPathHash>;

using ThreadPmuHistograms = std::unordered_map<uint32_t, PmuHistograms>;

}  // namespace callgraph
