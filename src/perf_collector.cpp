#include "callgraph/perf_collector.h"

#include <dirent.h>
#include <linux/perf_event.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <cinttypes>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <utility>

#include "callgraph/clock_converter.h"
#include "callgraph/common.h"

namespace callgraph {
namespace {

int perf_event_open(perf_event_attr* attr, pid_t pid, int cpu, int group_fd,
                    unsigned long flags)
{
    return static_cast<int>(
        syscall(SYS_perf_event_open, attr, pid, cpu, group_fd, flags));
}

void copy_ring_data(const char* data, size_t data_size, size_t offset,
                    void* out, size_t size)
{
    const size_t first = std::min(size, data_size - offset);
    memcpy(out, data + offset, first);
    if (first < size)
        memcpy(static_cast<char*>(out) + first, data, size - first);
}

}  // namespace

PerfCollector::PerfCollector(pid_t target, std::vector<PmuCounter> counters,
                             bool sampling, uint64_t sampling_period,
                             bool require, bool verbose)
    : target_(target), counters_(std::move(counters)), sampling_(sampling),
      sampling_period_(sampling_period), require_(require), verbose_(verbose)
{
}

PerfCollector::~PerfCollector()
{
    stop();
}

void PerfCollector::scan_tids(std::vector<uint32_t>* tids) const
{
    const std::string path =
        "/proc/" + std::to_string(static_cast<long long>(target_)) + "/task";
    DIR* dir = opendir(path.c_str());
    if (!dir)
        return;

    while (const dirent* entry = readdir(dir)) {
        char* end = nullptr;
        errno = 0;
        const unsigned long value = strtoul(entry->d_name, &end, 10);
        if (errno == 0 && end != entry->d_name && *end == '\0' &&
            value <= UINT32_MAX) {
            tids->push_back(static_cast<uint32_t>(value));
        }
    }
    closedir(dir);

    std::sort(tids->begin(), tids->end());
    tids->erase(std::unique(tids->begin(), tids->end()), tids->end());
}

void PerfCollector::start()
{
    if (started_)
        return;
    started_ = true;

    if (counters_.empty()) {
        unavailable_ = true;
        error_ = "no PMU counters requested";
        return;
    }

    std::vector<uint32_t> tids;
    scan_tids(&tids);
    for (uint32_t tid : tids)
        add_target_tid(tid);

    if (threads_.empty()) {
        unavailable_ = true;
        if (error_.empty())
            error_ = "no target threads found";
        if (require_)
            fail("PMU unavailable: %s", error_.c_str());
        log_warn("PMU unavailable: %s; set kernel.perf_event_paranoid <= 1 or "
                 "grant CAP_PERFMON",
                 error_.c_str());
    }
}

void PerfCollector::stop()
{
    if (!started_)
        return;
    started_ = false;

    for (auto& [tid, events] : threads_) {
        (void)tid;
        if (sampling_) {
            for (int fd : events.fds) {
                if (fd >= 0)
                    ioctl(fd, PERF_EVENT_IOC_DISABLE, 0);
            }
        } else if (events.leader_fd >= 0) {
            ioctl(events.leader_fd, PERF_EVENT_IOC_DISABLE,
                  PERF_IOC_FLAG_GROUP);
        }
    }

    read_counts();

    for (auto& [tid, events] : threads_) {
        (void)tid;
        close_thread(events);
    }
    threads_.clear();
    fds_.clear();
}

void PerfCollector::refresh_tids()
{
    if (!started_)
        return;
    std::vector<uint32_t> tids;
    scan_tids(&tids);
    for (uint32_t tid : tids)
        add_target_tid(tid);
}

void PerfCollector::add_target_tid(uint32_t tid)
{
    if (!started_ || counters_.empty())
        return;
    if (threads_.find(tid) != threads_.end())
        return;

    ThreadEvents events;
    events.tid = tid;
    events.counts.resize(counters_.size());

    const bool opened = sampling_ ? open_sampling_events(events)
                                  : open_counting_group(events);
    if (!opened) {
        close_thread(events);
        return;
    }

    bool enabled = true;
    if (sampling_) {
        for (int fd : events.fds) {
            if (ioctl(fd, PERF_EVENT_IOC_ENABLE, 0) != 0) {
                enabled = false;
                break;
            }
        }
    } else {
        enabled = ioctl(events.leader_fd, PERF_EVENT_IOC_ENABLE,
                        PERF_IOC_FLAG_GROUP) == 0;
    }

    if (!enabled) {
        if (error_.empty())
            error_ = "cannot enable perf events for tid " +
                     std::to_string(tid) + ": " + errno_string(errno);
        close_thread(events);
        return;
    }

    threads_.emplace(tid, std::move(events));
    rebuild_fd_list();
}

int PerfCollector::open_event(uint32_t tid, const PmuCounter& counter,
                              int group_fd, bool sampling, bool user_only,
                              bool* used_user_only, std::string* error)
{
    perf_event_attr attr = {};
    attr.type = counter.type;
    attr.size = sizeof(attr);
    attr.config = counter.config;
    attr.disabled = 1;
    attr.inherit = 0;
    attr.exclude_kernel = user_only ? 1 : 0;
    attr.exclude_hv = 0;

    if (sampling) {
        attr.sample_period = sampling_period_;
        attr.sample_type = PERF_SAMPLE_IP | PERF_SAMPLE_TID |
                           PERF_SAMPLE_TIME | PERF_SAMPLE_CPU |
                           PERF_SAMPLE_PERIOD;
        attr.read_format = PERF_FORMAT_TOTAL_TIME_ENABLED |
                           PERF_FORMAT_TOTAL_TIME_RUNNING;
        attr.use_clockid = 1;
        attr.clockid = CLOCK_MONOTONIC;
        attr.wakeup_events = 1;
    } else {
        attr.read_format = PERF_FORMAT_GROUP |
                           PERF_FORMAT_TOTAL_TIME_ENABLED |
                           PERF_FORMAT_TOTAL_TIME_RUNNING;
    }

    int fd = perf_event_open(&attr, static_cast<pid_t>(tid), -1, group_fd,
                             PERF_FLAG_FD_CLOEXEC);

    // use_clockid needs a modern perf ABI.  Fall back to the default clock
    // rather than losing the counter on an older kernel.
    if (fd < 0 && sampling && attr.use_clockid == 1 && errno == EINVAL) {
        attr.use_clockid = 0;
        attr.clockid = 0;
        fd = perf_event_open(&attr, static_cast<pid_t>(tid), -1, group_fd,
                             PERF_FLAG_FD_CLOEXEC);
    }

    // perf_event_paranoid=2 allows user-space measurement only.  Retry
    // without kernel time so the counter is still useful.
    if (fd < 0 && !user_only && (errno == EACCES || errno == EPERM)) {
        attr.exclude_kernel = 1;
        fd = perf_event_open(&attr, static_cast<pid_t>(tid), -1, group_fd,
                             PERF_FLAG_FD_CLOEXEC);
        if (fd >= 0 && used_user_only)
            *used_user_only = true;
    }

    if (fd < 0) {
        if (error) {
            *error = "perf_event_open(" + counter.name + ") failed: " +
                     errno_string(errno);
        }
        return -1;
    }
    return fd;
}

bool PerfCollector::open_counting_group(ThreadEvents& events)
{
    bool any = false;
    bool user_only = false;
    bool saw_user_only = false;
    bool saw_kernel = false;

    for (size_t i = 0; i < counters_.size(); ++i) {
        bool used_user_only = false;
        std::string error;
        const int group_fd = events.fds.empty() ? -1 : events.leader_fd;
        const int fd = open_event(events.tid, counters_[i], group_fd, false,
                                  user_only, &used_user_only, &error);
        if (fd < 0) {
            if (error_.empty())
                error_ = error;
            if (require_)
                fail("PMU unavailable: %s", error.c_str());
            if (verbose_)
                log_verbose("PMU %s unavailable for tid %u: %s",
                            counters_[i].name.c_str(), events.tid,
                            error.c_str());
            continue;
        }

        if (events.fds.empty()) {
            events.leader_fd = fd;
            user_only = used_user_only;
        }
        if (used_user_only)
            saw_user_only = true;
        else
            saw_kernel = true;

        events.fds.push_back(fd);
        events.counter_indices.push_back(i);
        any = true;
    }

    events.user_only = saw_user_only && !saw_kernel;
    return any;
}

bool PerfCollector::open_sampling_events(ThreadEvents& events)
{
    bool any = false;
    bool saw_user_only = false;
    bool saw_kernel = false;

    for (size_t i = 0; i < counters_.size(); ++i) {
        bool used_user_only = false;
        std::string error;
        const int fd = open_event(events.tid, counters_[i], -1, true, false,
                                  &used_user_only, &error);
        if (fd < 0) {
            if (error_.empty())
                error_ = error;
            if (require_)
                fail("PMU unavailable: %s", error.c_str());
            if (verbose_)
                log_verbose("PMU %s unavailable for tid %u: %s",
                            counters_[i].name.c_str(), events.tid,
                            error.c_str());
            continue;
        }

        Ring ring;
        ring.fd = fd;
        ring.counter_index = i;
        if (!map_ring(&ring, &error)) {
            close(fd);
            if (error_.empty())
                error_ = error;
            if (require_)
                fail("PMU unavailable: %s", error.c_str());
            if (verbose_)
                log_verbose("PMU %s ring unavailable for tid %u: %s",
                            counters_[i].name.c_str(), events.tid,
                            error.c_str());
            continue;
        }

        if (used_user_only)
            saw_user_only = true;
        else
            saw_kernel = true;

        events.fds.push_back(fd);
        events.counter_indices.push_back(i);
        events.rings.push_back(ring);
        any = true;
    }

    events.user_only = saw_user_only && !saw_kernel;
    return any;
}

bool PerfCollector::map_ring(Ring* ring, std::string* error)
{
    const long page = sysconf(_SC_PAGESIZE);
    if (page <= 0) {
        if (error)
            *error = "cannot determine the system page size";
        return false;
    }

    size_t pages = 8;
    while (true) {
        const size_t data_size = pages * static_cast<size_t>(page);
        const size_t map_size = data_size + static_cast<size_t>(page);
        void* base = mmap(nullptr, map_size, PROT_READ | PROT_WRITE,
                          MAP_SHARED, ring->fd, 0);
        if (base != MAP_FAILED) {
            ring->base = base;
            ring->data_size = data_size;
            ring->map_size = map_size;
            return true;
        }
        if (pages == 1)
            break;
        pages = 1;
    }

    if (error)
        *error = "mmap perf ring failed: " + errno_string(errno);
    return false;
}

void PerfCollector::drain(const std::function<void(const PmuSample&)>& on_sample)
{
    for (auto& [tid, events] : threads_) {
        (void)tid;
        for (Ring& ring : events.rings)
            drain_ring(ring, on_sample);
    }
}

void PerfCollector::drain_ring(
    Ring& ring, const std::function<void(const PmuSample&)>& on_sample)
{
    auto* meta = static_cast<perf_event_mmap_page*>(ring.base);
    if (!meta)
        return;

    const char* base = static_cast<const char*>(ring.base);
    const size_t data_offset =
        meta->data_offset != 0 ? static_cast<size_t>(meta->data_offset) : 0;
    const size_t data_size =
        meta->data_size != 0 ? static_cast<size_t>(meta->data_size)
                             : ring.data_size;
    if (data_offset == 0 || data_size == 0 ||
        (data_size & (data_size - 1)) != 0)
        return;

    const char* data = base + data_offset;
    uint64_t head = __atomic_load_n(&meta->data_head, __ATOMIC_ACQUIRE);
    uint64_t tail = meta->data_tail;

    while (tail < head) {
        const size_t offset =
            static_cast<size_t>(tail) & (data_size - 1);

        perf_event_header header = {};
        copy_ring_data(data, data_size, offset, &header, sizeof(header));
        if (header.size < sizeof(header) || header.size > data_size)
            break;

        std::vector<char> record(header.size);
        copy_ring_data(data, data_size, offset, record.data(), header.size);

        if (header.type == PERF_RECORD_SAMPLE) {
            PmuSample sample;
            if (parse_perf_sample(record.data(), record.size(),
                                  static_cast<uint32_t>(ring.counter_index),
                                  ClockConverter::now_monotonic_ns(), &sample)) {
                ++samples_;
                if (on_sample)
                    on_sample(sample);
            }
        } else if (header.type == PERF_RECORD_LOST) {
            uint64_t lost = 0;
            if (parse_perf_lost(record.data(), record.size(), &lost))
                lost_ += lost;
        }

        tail += header.size;
    }

    __atomic_store_n(&meta->data_tail, tail, __ATOMIC_RELEASE);
}

void PerfCollector::read_counts()
{
    counts_.clear();
    for (auto& [tid, events] : threads_) {
        PmuThreadCounts thread;
        thread.tid = tid;
        thread.user_only = events.user_only;
        thread.values.resize(counters_.size());

        if (sampling_) {
            for (size_t i = 0; i < events.fds.size(); ++i) {
                uint64_t values[3] = {};
                const ssize_t got =
                    read(events.fds[i], values, sizeof(values));
                if (got == static_cast<ssize_t>(sizeof(values))) {
                    const size_t index = events.counter_indices[i];
                    if (index < thread.values.size()) {
                        thread.values[index] = {
                            values[0], values[1], values[2], true};
                    }
                }
            }
        } else {
            const size_t count = events.fds.size();
            if (count != 0) {
                std::vector<uint64_t> values(1 + 2 + count);
                const ssize_t got =
                    read(events.leader_fd, values.data(),
                         values.size() * sizeof(uint64_t));
                if (got >= static_cast<ssize_t>((3 + count) *
                                                sizeof(uint64_t))) {
                    const uint64_t nr = values[0];
                    const uint64_t enabled = values[1];
                    const uint64_t running = values[2];
                    for (size_t i = 0; i < count && i < nr; ++i) {
                        const size_t index = events.counter_indices[i];
                        if (index < thread.values.size()) {
                            thread.values[index] = {
                                values[3 + i], enabled, running, true};
                        }
                    }
                }
            }
        }

        counts_.push_back(std::move(thread));
    }

    std::sort(counts_.begin(), counts_.end(),
              [](const PmuThreadCounts& left, const PmuThreadCounts& right) {
                  return left.tid < right.tid;
              });
}

void PerfCollector::close_thread(ThreadEvents& events)
{
    for (Ring& ring : events.rings) {
        if (ring.base)
            munmap(ring.base, ring.map_size);
    }
    events.rings.clear();

    for (int fd : events.fds) {
        if (fd >= 0)
            close(fd);
    }
    events.fds.clear();
    events.leader_fd = -1;
}

void PerfCollector::rebuild_fd_list()
{
    fds_.clear();
    for (auto& [tid, events] : threads_) {
        (void)tid;
        fds_.insert(fds_.end(), events.fds.begin(), events.fds.end());
    }
}

std::string PerfCollector::format_counts() const
{
    return format_pmu_counts(counters_, counts_);
}

bool parse_perf_sample(const char* data, size_t size, uint32_t counter_index,
                       uint64_t receipt_ns, PmuSample* sample)
{
    if (!data || !sample || size < sizeof(perf_event_header))
        return false;

    perf_event_header header = {};
    memcpy(&header, data, sizeof(header));
    if (header.type != PERF_RECORD_SAMPLE ||
        header.size < sizeof(header) || header.size > size)
        return false;

    // PERF_SAMPLE_IP | TID | TIME | CPU | PERIOD writes, in order:
    //   u64 ip; u32 pid; u32 tid; u64 time; u32 cpu; u32 res; u64 period
    constexpr size_t kFields = 8 + 8 + 8 + 8 + 8;
    if (header.size < sizeof(header) + kFields)
        return false;

    size_t offset = sizeof(header);
    uint64_t ip = 0;
    uint32_t pid = 0;
    uint32_t tid = 0;
    uint64_t time = 0;
    uint32_t cpu = 0;
    uint32_t res = 0;
    uint64_t period = 0;

    memcpy(&ip, data + offset, sizeof(ip));
    offset += sizeof(ip);
    memcpy(&pid, data + offset, sizeof(pid));
    offset += sizeof(pid);
    memcpy(&tid, data + offset, sizeof(tid));
    offset += sizeof(tid);
    memcpy(&time, data + offset, sizeof(time));
    offset += sizeof(time);
    memcpy(&cpu, data + offset, sizeof(cpu));
    offset += sizeof(cpu);
    memcpy(&res, data + offset, sizeof(res));
    offset += sizeof(res);
    memcpy(&period, data + offset, sizeof(period));
    (void)pid;
    (void)res;

    sample->ip = ip;
    sample->tid = tid;
    sample->ts = time != 0 ? time : receipt_ns;
    sample->timestamp_from_receipt = time == 0;
    sample->cpu = cpu;
    sample->period = period;
    sample->event_index = counter_index;
    return true;
}

bool parse_perf_lost(const char* data, size_t size, uint64_t* lost)
{
    if (!data || !lost || size < sizeof(perf_event_header) + 16)
        return false;

    perf_event_header header = {};
    memcpy(&header, data, sizeof(header));
    if (header.type != PERF_RECORD_LOST ||
        header.size < sizeof(header) + 16 || header.size > size)
        return false;

    size_t offset = sizeof(header);
    uint64_t id = 0;
    uint64_t count = 0;
    memcpy(&id, data + offset, sizeof(id));
    offset += sizeof(id);
    memcpy(&count, data + offset, sizeof(count));
    (void)id;

    *lost = count;
    return true;
}

}  // namespace callgraph
