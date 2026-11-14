#pragma once

#include <cstddef>
#include <cstdint>
#include <unordered_map>
#include <vector>

namespace callgraph {

// Sentinel parent used for calls that have no instrumented caller.
inline constexpr uint64_t kRootFunction = UINT64_MAX;

// Bucket 0 is exactly 0 ns.  Bucket k >= 1 covers [2^(k-1), 2^k) ns, so the
// array needs an entry for every bit width up to 64.
inline constexpr int kLatencyBuckets = 65;

int latency_bucket(uint64_t ns);

struct LatencyHistogram {
    uint64_t calls = 0;
    uint64_t total_ns = 0;
    uint64_t min_ns = UINT64_MAX;
    uint64_t max_ns = 0;
    uint64_t buckets[kLatencyBuckets] = {};

    void add(uint64_t ns);
};

// A call path is the sequence of function ids from a root to a node.  Edges
// keyed by the full path keep every tree node's total consistent with the
// totals of the children rendered beneath it.  Keying only the immediate
// caller merges all call sites of a function: a node reached from one caller
// then shows that caller's slice while its children show calls made by every
// other caller, so a child total can dwarf its parent.
using CallPath = std::vector<uint64_t>;

struct CallPathHash {
    size_t operator()(const CallPath& path) const noexcept;
};

struct ThreadLatency {
    // Histogram per exact call path (root -> node).
    std::unordered_map<CallPath, LatencyHistogram, CallPathHash> paths;
    // Sequence in which each path was first recorded.  Sibling calls on one
    // thread cannot overlap, so completion order is also call order; the tree
    // uses it to list siblings in the order they occurred.
    std::unordered_map<CallPath, uint64_t, CallPathHash> path_sequence;
    uint64_t next_sequence = 0;
    // Frames still live at shutdown, root-first.  They anchor completed child
    // subtrees whose caller never returned.
    std::vector<uint64_t> live_stack;
    uint64_t incomplete = 0;
};

// Per-thread latency statistics.  Only the collector thread touches this, so
// no locking is needed; the report is rendered after collection stops.
class LatencyStats {
public:
    // Records one completed call.  `path` runs root-first and ends with the
    // returning function, so distinct callers of the same function stay apart.
    void record(uint32_t tid, const CallPath& path, uint64_t ns);
    void mark_incomplete(uint32_t tid, uint64_t count = 1);
    void mark_live(uint32_t tid, const std::vector<uint64_t>& stack);

    const std::unordered_map<uint32_t, ThreadLatency>& threads() const
    {
        return threads_;
    }

private:
    std::unordered_map<uint32_t, ThreadLatency> threads_;
};

}  // namespace callgraph
