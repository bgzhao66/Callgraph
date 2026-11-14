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

size_t CallPathHash::operator()(const CallPath& path) const noexcept
{
    // FNV-1a over the function ids; paths are short and usually share a long
    // prefix, but the exact key keeps every call site separate.
    uint64_t hash = 1469598103934665603ULL;
    for (uint64_t function_id : path) {
        hash ^= function_id;
        hash *= 1099511628211ULL;
    }
    return static_cast<size_t>(hash);
}

void LatencyStats::record(uint32_t tid, const CallPath& path, uint64_t ns)
{
    if (path.empty())
        return;

    ThreadLatency& thread = threads_[tid];
    auto [it, inserted] = thread.paths.try_emplace(path);
    if (inserted)
        thread.path_sequence.emplace(path, thread.next_sequence++);
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
