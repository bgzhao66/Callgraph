#pragma once

#include <cstdint>

namespace callgraph {

// Log-scale histogram of whole-trace durations.  One sample is added per
// closed root trace, so the quantile describes traces rather than spans.
//
// Buckets are octaves subdivided into 16 parts.  That gives roughly 6%
// resolution above 16ns, which is fine for a tail-sampling threshold and
// much cheaper than keeping every duration.
class TraceDurationHistogram {
public:
    static constexpr int kOctaves = 64;
    static constexpr int kSubBuckets = 16;
    static constexpr int kBuckets = kOctaves * kSubBuckets;

    void add(uint64_t ns);

    uint64_t count() const { return count_; }

    // Lower bound of the bucket containing the q-quantile, q in [0,1].
    uint64_t quantile(double q) const;

    // Estimated fraction of samples at or below ns.  The estimate uses the
    // midpoint of the containing bucket, so the maximum trace is slightly
    // below 1.0 rather than exactly 1.0.
    double cdf(uint64_t ns) const;

private:
    static int bucket_index(uint64_t ns);
    static uint64_t bucket_lower(int index);

    uint64_t buckets_[kBuckets] = {};
    uint64_t count_ = 0;
};

}  // namespace callgraph
