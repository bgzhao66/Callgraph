#pragma once

#include <string>
#include <vector>

#include "callgraph/latency_stats.h"

namespace callgraph {

// Renders the per-thread latency histogram tree.  The report is a pure
// function of the collected statistics and the function-name table.
std::string format_histogram_report(const LatencyStats& stats,
                                    const std::vector<std::string>& names);

}  // namespace callgraph
