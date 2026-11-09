#include "callgraph/output.h"

#include <cerrno>
#include <cstring>
#include <unistd.h>

#include "callgraph/common.h"

namespace callgraph {

Output::Output(const std::string& path)
{
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

void Output::emit(uint64_t ts, uint32_t tid, uint32_t depth, const char* arrow,
                  const std::string& name)
{
    char prefix[80];
    const int n = snprintf(prefix, sizeof(prefix), "%llu %u : %u %s ",
                           static_cast<unsigned long long>(ts), tid, depth, arrow);

    std::string line;
    line.reserve(static_cast<size_t>(n) + name.size() + 1);
    line.append(prefix, static_cast<size_t>(n));
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
