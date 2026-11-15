#include "callgraph/trace_duration_histogram.h"

#include <algorithm>
#include <cmath>

namespace callgraph {

int TraceDurationHistogram::bucket_index(uint64_t ns)
{
    if (ns == 0)
        return 0;

    const int octave = 63 - __builtin_clzll(ns);
    if (octave < 4)
        return octave * kSubBuckets;

    const uint64_t base = 1ULL << octave;
    const int sub = static_cast<int>((ns - base) >> (octave - 4));
    return octave * kSubBuckets + sub;
}

uint64_t TraceDurationHistogram::bucket_lower(int index)
{
    if (index <= 0)
        return 0;

    const int octave = index / kSubBuckets;
    const int sub = index % kSubBuckets;
    const uint64_t base = 1ULL << octave;
    if (octave < 4)
        return base;
    return base + (static_cast<uint64_t>(sub) << (octave - 4));
}

void TraceDurationHistogram::add(uint64_t ns)
{
    ++buckets_[bucket_index(ns)];
    ++count_;
}

uint64_t TraceDurationHistogram::quantile(double q) const
{
    if (count_ == 0)
        return 0;
    if (q <= 0.0)
        return bucket_lower(0);

    uint64_t target = static_cast<uint64_t>(std::ceil(q * count_));
    if (target == 0)
        target = 1;
    if (target > count_)
        target = count_;

    uint64_t cumulative = 0;
    for (int i = 0; i < kBuckets; ++i) {
        cumulative += buckets_[i];
        if (cumulative >= target)
            return bucket_lower(i);
    }
    return bucket_lower(kBuckets - 1);
}

double TraceDurationHistogram::cdf(uint64_t ns) const
{
    if (count_ == 0)
        return 0.0;

    const int index = bucket_index(ns);
    uint64_t before = 0;
    for (int i = 0; i < index; ++i)
        before += buckets_[i];

    const double midpoint = before + 0.5 * buckets_[index];
    return std::clamp(midpoint / count_, 0.0, 1.0);
}

}  // namespace callgraph
