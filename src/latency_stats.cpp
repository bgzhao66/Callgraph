#include "callgraph/latency_stats.h"

namespace callgraph {

int latency_bucket(uint64_t ns)
{
    if (ns == 0)
        return 0;

    int bucket = 0;
    while (ns != 0) {
        ++bucket;
        ns >>= 1;
    }
    return bucket;
}

void LatencyHistogram::add(uint64_t ns)
{
    ++calls;
    total_ns += ns;
    if (ns < min_ns)
        min_ns = ns;
    if (ns > max_ns)
        max_ns = ns;
    ++buckets[latency_bucket(ns)];
}

size_t EdgeKeyHash::operator()(const EdgeKey& key) const noexcept
{
    // Mix both ids; function ids are dense, so a simple combine is enough.
    uint64_t hash = key.parent * 0x9e3779b97f4a7c15ULL;
    hash ^= key.child + 0x9e3779b97f4a7c15ULL + (hash << 6) + (hash >> 2);
    return static_cast<size_t>(hash);
}

void LatencyStats::record(uint32_t tid, uint64_t parent, uint64_t child,
                          uint64_t ns)
{
    ThreadLatency& thread = threads_[tid];
    const EdgeKey key{parent, child};
    auto [it, inserted] = thread.edges.try_emplace(key);
    if (inserted)
        thread.edge_sequence.emplace(key, thread.next_sequence++);
    it->second.add(ns);
}

void LatencyStats::mark_incomplete(uint32_t tid, uint64_t count)
{
    if (count == 0)
        return;
    threads_[tid].incomplete += count;
}

void LatencyStats::mark_live(uint32_t tid, const std::vector<uint64_t>& stack)
{
    if (stack.empty())
        return;
    threads_[tid].live_stack = stack;
}

}  // namespace callgraph
