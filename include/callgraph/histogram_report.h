#pragma once

#include <string>
#include <unordered_map>
#include <vector>

#include "callgraph/kernel_histogram.h"
#include "callgraph/latency_stats.h"

namespace callgraph {

// Renders the latency histogram report: one tree/histogram pair per root.
// The report is a pure function of the collected statistics and the
// function-name table.
//
// When kernel histograms are supplied, each user-frame histogram is followed
// by a separate `kernel:` block containing the kernel events observed on that
// exact call path.  Samples are keyed by the full root-first path, so two
// roots that call the same function at the same depth stay separate.
std::string format_histogram_report(
    const LatencyStats& stats, const std::vector<std::string>& names,
    const std::unordered_map<uint32_t, KernelEventHistograms>*
        kernel_histograms = nullptr);

}  // namespace callgraph
