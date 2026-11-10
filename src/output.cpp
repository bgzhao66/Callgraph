#include "callgraph/output.h"

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <ctime>
#include <time.h>
#include <unistd.h>

#include "callgraph/common.h"

namespace callgraph {

Output::Output(const std::string& path, TimestampMode mode, size_t indent_step)
    : mode_(mode), indent_step_(indent_step)
{
    if (mode_ == TimestampMode::WallClock) {
        struct timespec monotonic = {};
        struct timespec realtime = {};
        if (clock_gettime(CLOCK_MONOTONIC, &monotonic) != 0 ||
            clock_gettime(CLOCK_REALTIME, &realtime) != 0) {
            fail("cannot read the system clock: %s",
                 errno_string(errno).c_str());
        }
        wall_offset_ns_ =
            (static_cast<int64_t>(realtime.tv_sec - monotonic.tv_sec) *
                 1000000000LL) +
            (realtime.tv_nsec - monotonic.tv_nsec);
    }

    if (path.empty() || path == "-") {
        fp_ = stdout;
        own_fp_ = false;
    } else {
        fp_ = fopen(path.c_str(), "w");
        if (!fp_)
            fail("cannot open %s: %s", path.c_str(), errno_string(errno).c_str());
        own_fp_ = true;
    }

    const bool tty = isatty(fileno(fp_)) != 0;
    setvbuf(fp_, nullptr, tty ? _IOLBF : _IOFBF, 1u << 20);

    thread_ = std::thread(&Output::worker, this);
}

Output::~Output()
{
    stop();
    if (own_fp_ && fp_)
        fclose(fp_);
}

std::string Output::format_timestamp(uint64_t ts_ns) const
{
    if (mode_ == TimestampMode::BootSeconds) {
        char buffer[64];
        snprintf(buffer, sizeof(buffer), "%llu.%09llu",
                 static_cast<unsigned long long>(ts_ns / 1000000000ULL),
                 static_cast<unsigned long long>(ts_ns % 1000000000ULL));
        return buffer;
    }

    // The monotonic clock does not count suspend time and the wall-clock
    // offset is sampled at startup, so this is an approximation if the system
    // clock is stepped or the machine suspends while tracing.
    const int64_t wall_ns = static_cast<int64_t>(ts_ns) + wall_offset_ns_;
    time_t seconds = static_cast<time_t>(wall_ns / 1000000000LL);
    long nanos = static_cast<long>(wall_ns % 1000000000LL);
    if (nanos < 0) {
        nanos += 1000000000L;
        seconds -= 1;
    }

    struct tm local = {};
    if (!localtime_r(&seconds, &local))
        return "0000-00-00T00:00:00.000000000+00:00";

    char date_time[64];
    if (strftime(date_time, sizeof(date_time), "%Y-%m-%dT%H:%M:%S", &local) == 0)
        return "0000-00-00T00:00:00.000000000+00:00";

    const long offset = local.tm_gmtoff;
    const char sign = offset < 0 ? '-' : '+';
    const long magnitude = offset < 0 ? -offset : offset;

    char buffer[96];
    snprintf(buffer, sizeof(buffer), "%s.%09ld%c%02ld:%02ld", date_time, nanos,
             sign, magnitude / 3600, (magnitude % 3600) / 60);
    return buffer;
}

void Output::emit(uint64_t ts, uint32_t tid, uint32_t depth, const char* arrow,
                  const std::string& name)
{
    const std::string stamp = format_timestamp(ts);

    char suffix[80];
    const int suffix_length = snprintf(suffix, sizeof(suffix), " %u : %u %s ",
                                       tid, depth, arrow);

    // Keep the arrow column fixed; only the name moves.  Cap the indent so a
    // pathological --indent/depth combination cannot grow a line without bound.
    size_t indent = 0;
    if (indent_step_ != 0 && depth != 0) {
        constexpr size_t kMaxIndent = 4096;
        if (indent_step_ > kMaxIndent / depth)
            indent = kMaxIndent;
        else
            indent = static_cast<size_t>(depth) * indent_step_;
    }

    std::string line;
    line.reserve(stamp.size() + static_cast<size_t>(suffix_length) + indent +
                 name.size() + 1);
    line.append(stamp);
    line.append(suffix, static_cast<size_t>(suffix_length));
    line.append(indent, ' ');
    line.append(name);
    line.push_back('\n');

    {
        std::lock_guard<std::mutex> lock(mu_);
        if (stop_ || queued_bytes_ + line.size() > kMaxQueuedBytes) {
            dropped_.fetch_add(1, std::memory_order_relaxed);
            return;
        }
        queued_bytes_ += line.size();
        queue_.push_back(std::move(line));
    }
    cv_.notify_one();
}

void Output::stop()
{
    {
        std::lock_guard<std::mutex> lock(mu_);
        if (stop_)
            return;
        stop_ = true;
    }
    cv_.notify_all();

    if (thread_.joinable())
        thread_.join();

    if (fp_)
        fflush(fp_);
}

void Output::worker()
{
    std::deque<std::string> batch;
    bool warned = false;

    while (true) {
        {
            std::unique_lock<std::mutex> lock(mu_);
            cv_.wait(lock, [this] { return stop_ || !queue_.empty(); });
            if (queue_.empty() && stop_)
                break;
            batch.swap(queue_);
            queued_bytes_ = 0;
        }

        for (const auto& line : batch) {
            const size_t written = fwrite(line.data(), 1, line.size(), fp_);
            if (written != line.size() && !warned) {
                warned = true;
                log_warn("output write failed: %s", errno_string(errno).c_str());
            }
        }
        batch.clear();
        fflush(fp_);
    }

    fflush(fp_);
}

}  // namespace callgraph
