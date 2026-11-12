#pragma once

#include <cstdint>

namespace callgraph {

// Samples the offset between CLOCK_REALTIME and CLOCK_MONOTONIC.
//
// bpf_ktime_get_ns() returns CLOCK_MONOTONIC nanoseconds.  OTLP timestamps are
// Unix epoch nanoseconds, so every exported timestamp is shifted by this
// offset.  The offset is sampled at startup and can be recalibrated during a
// long-running session.  Durations are always derived from monotonic
// timestamps (see SpanGenerator), so a wall-clock step does not change them.
class ClockConverter {
public:
    ClockConverter();

    int64_t offset_ns() const { return offset_ns_; }

    // Resamples the realtime/monotonic relationship.  Calibration is done by
    // bracketing the monotonic read between two realtime reads.
    void recalibrate();

    uint64_t to_unix_ns(uint64_t monotonic_ns) const;
    static uint64_t now_monotonic_ns();

private:
    int64_t offset_ns_ = 0;
};

}  // namespace callgraph
