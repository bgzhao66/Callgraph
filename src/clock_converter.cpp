#include "callgraph/clock_converter.h"

#include <cerrno>
#include <time.h>

#include "callgraph/common.h"

namespace callgraph {

ClockConverter::ClockConverter()
{
    recalibrate();
}

void ClockConverter::recalibrate()
{
    struct timespec realtime_before = {};
    struct timespec monotonic = {};
    struct timespec realtime_after = {};

    if (clock_gettime(CLOCK_REALTIME, &realtime_before) != 0 ||
        clock_gettime(CLOCK_MONOTONIC, &monotonic) != 0 ||
        clock_gettime(CLOCK_REALTIME, &realtime_after) != 0) {
        fail("cannot read the system clock: %s",
             errno_string(errno).c_str());
    }

    const auto to_ns = [](const struct timespec& ts) -> int64_t {
        return static_cast<int64_t>(ts.tv_sec) * 1000000000LL +
               static_cast<int64_t>(ts.tv_nsec);
    };

    const int64_t realtime_mid =
        to_ns(realtime_before) + (to_ns(realtime_after) - to_ns(realtime_before)) / 2;
    offset_ns_ = realtime_mid - to_ns(monotonic);
}

uint64_t ClockConverter::to_unix_ns(uint64_t monotonic_ns) const
{
    const int64_t value = static_cast<int64_t>(monotonic_ns) + offset_ns_;
    return value < 0 ? 0 : static_cast<uint64_t>(value);
}

uint64_t ClockConverter::now_monotonic_ns()
{
    struct timespec now = {};
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0)
        fail("cannot read CLOCK_MONOTONIC: %s", errno_string(errno).c_str());
    return static_cast<uint64_t>(now.tv_sec) * 1000000000ULL +
           static_cast<uint64_t>(now.tv_nsec);
}

}  // namespace callgraph
