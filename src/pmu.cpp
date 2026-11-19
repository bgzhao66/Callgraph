#include "callgraph/pmu.h"

#include <linux/perf_event.h>

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <cinttypes>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <string>

namespace callgraph {
namespace {

constexpr uint64_t hw_cache_config(uint64_t cache, uint64_t op,
                                   uint64_t result)
{
    return cache | (op << 8) | (result << 16);
}

struct CounterEntry {
    const char* name;
    uint32_t type;
    uint64_t config;
};

constexpr CounterEntry kCounters[] = {
    {"cycles", PERF_TYPE_HARDWARE, PERF_COUNT_HW_CPU_CYCLES},
    {"instructions", PERF_TYPE_HARDWARE, PERF_COUNT_HW_INSTRUCTIONS},
    {"cache-references", PERF_TYPE_HARDWARE, PERF_COUNT_HW_CACHE_REFERENCES},
    {"cache-misses", PERF_TYPE_HARDWARE, PERF_COUNT_HW_CACHE_MISSES},
    {"branch-instructions", PERF_TYPE_HARDWARE,
     PERF_COUNT_HW_BRANCH_INSTRUCTIONS},
    {"branch-misses", PERF_TYPE_HARDWARE, PERF_COUNT_HW_BRANCH_MISSES},
    {"bus-cycles", PERF_TYPE_HARDWARE, PERF_COUNT_HW_BUS_CYCLES},
    {"ref-cycles", PERF_TYPE_HARDWARE, PERF_COUNT_HW_REF_CPU_CYCLES},
    {"stalled-cycles-frontend", PERF_TYPE_HARDWARE,
     PERF_COUNT_HW_STALLED_CYCLES_FRONTEND},
    {"stalled-cycles-backend", PERF_TYPE_HARDWARE,
     PERF_COUNT_HW_STALLED_CYCLES_BACKEND},
    {"L1-dcache-load-misses", PERF_TYPE_HW_CACHE,
     hw_cache_config(PERF_COUNT_HW_CACHE_L1D, PERF_COUNT_HW_CACHE_OP_READ,
                     PERF_COUNT_HW_CACHE_RESULT_MISS)},
    {"L1-icache-load-misses", PERF_TYPE_HW_CACHE,
     hw_cache_config(PERF_COUNT_HW_CACHE_L1I, PERF_COUNT_HW_CACHE_OP_READ,
                     PERF_COUNT_HW_CACHE_RESULT_MISS)},
    {"LLC-load-misses", PERF_TYPE_HW_CACHE,
     hw_cache_config(PERF_COUNT_HW_CACHE_LL, PERF_COUNT_HW_CACHE_OP_READ,
                     PERF_COUNT_HW_CACHE_RESULT_MISS)},
    {"dTLB-load-misses", PERF_TYPE_HW_CACHE,
     hw_cache_config(PERF_COUNT_HW_CACHE_DTLB, PERF_COUNT_HW_CACHE_OP_READ,
                     PERF_COUNT_HW_CACHE_RESULT_MISS)},
    {"iTLB-load-misses", PERF_TYPE_HW_CACHE,
     hw_cache_config(PERF_COUNT_HW_CACHE_ITLB, PERF_COUNT_HW_CACHE_OP_READ,
                     PERF_COUNT_HW_CACHE_RESULT_MISS)},
};

struct CounterAlias {
    const char* alias;
    const char* name;
};

constexpr CounterAlias kAliases[] = {
    {"cpu-cycles", "cycles"},
    {"branches", "branch-instructions"},
    {"branch-instruction", "branch-instructions"},
    {"cache-miss", "cache-misses"},
    {"cache-reference", "cache-references"},
    {"branch", "branch-instructions"},
};

const CounterEntry* find_entry(const std::string& name)
{
    for (const CounterEntry& entry : kCounters) {
        if (name == entry.name)
            return &entry;
    }
    for (const CounterAlias& alias : kAliases) {
        if (name == alias.alias) {
            for (const CounterEntry& entry : kCounters) {
                if (std::string(entry.name) == alias.name)
                    return &entry;
            }
        }
    }
    return nullptr;
}

std::string trim(const std::string& text)
{
    size_t begin = 0;
    while (begin < text.size() &&
           std::isspace(static_cast<unsigned char>(text[begin])) != 0)
        ++begin;
    size_t end = text.size();
    while (end > begin &&
           std::isspace(static_cast<unsigned char>(text[end - 1])) != 0)
        --end;
    return text.substr(begin, end - begin);
}

bool parse_raw_counter(const std::string& text, PmuCounter* out)
{
    if (text.size() < 2 || (text[0] != 'r' && text[0] != 'R'))
        return false;
    for (size_t i = 1; i < text.size(); ++i) {
        if (std::isxdigit(static_cast<unsigned char>(text[i])) == 0)
            return false;
    }
    errno = 0;
    char* end = nullptr;
    const unsigned long long config =
        strtoull(text.c_str() + 1, &end, 16);
    if (errno != 0 || end == text.c_str() + 1 || *end != '\0')
        return false;
    out->name = text;
    out->type = PERF_TYPE_RAW;
    out->config = config;
    return true;
}

std::string format_seconds(uint64_t ns)
{
    constexpr uint64_t kNanosecondsPerSecond = 1000000000;
    char buffer[64];
    snprintf(buffer, sizeof(buffer), "%" PRIu64 ".%09" PRIu64 "s",
             ns / kNanosecondsPerSecond, ns % kNanosecondsPerSecond);
    return buffer;
}

}  // namespace

std::vector<PmuCounter> default_pmu_counters()
{
    static const char* const kDefaults[] = {
        "cycles", "instructions", "cache-misses", "branch-misses"};
    std::vector<PmuCounter> counters;
    for (const char* name : kDefaults) {
        const CounterEntry* entry = find_entry(name);
        if (entry)
            counters.push_back({entry->name, entry->type, entry->config});
    }
    return counters;
}

bool parse_pmu_counter(const std::string& text, PmuCounter* out,
                       std::string* error)
{
    const std::string name = trim(text);
    if (name.empty()) {
        if (error)
            *error = "PMU counter name is empty";
        return false;
    }

    if (const CounterEntry* entry = find_entry(name)) {
        out->name = entry->name;
        out->type = entry->type;
        out->config = entry->config;
        return true;
    }
    if (parse_raw_counter(name, out))
        return true;

    if (error) {
        *error = "unknown PMU counter '" + name + "'; supported: " +
                 supported_pmu_counters();
    }
    return false;
}

bool parse_pmu_counters(const std::string& list, std::vector<PmuCounter>* out,
                        std::string* error)
{
    size_t start = 0;
    while (start <= list.size()) {
        const size_t comma = list.find(',', start);
        const std::string name =
            list.substr(start, comma == std::string::npos
                                   ? std::string::npos
                                   : comma - start);
        PmuCounter counter;
        if (!parse_pmu_counter(name, &counter, error))
            return false;

        bool present = false;
        for (const PmuCounter& existing : *out) {
            if (existing.name == counter.name) {
                present = true;
                break;
            }
        }
        if (!present)
            out->push_back(std::move(counter));

        if (comma == std::string::npos)
            break;
        start = comma + 1;
    }
    return true;
}

std::string supported_pmu_counters()
{
    std::string out;
    for (const CounterEntry& entry : kCounters) {
        if (!out.empty())
            out += ", ";
        out += entry.name;
    }
    out += ", or r<hex>";
    return out;
}

std::string format_pmu_counts(const std::vector<PmuCounter>& counters,
                              const std::vector<PmuThreadCounts>& threads)
{
    if (threads.empty())
        return {};

    size_t width = 7;
    for (const PmuCounter& counter : counters)
        width = std::max(width, counter.name.size());

    std::string out = "PMU counters (raw, not scaled):\n";
    for (const PmuThreadCounts& thread : threads) {
        out += "  tid ";
        out += std::to_string(thread.tid);
        if (thread.user_only)
            out += "  user-only";
        out += '\n';

        for (size_t i = 0; i < counters.size(); ++i) {
            out += "    ";
            out += counters[i].name;
            out.append(width - counters[i].name.size(), ' ');
            out += "  ";

            const PmuCountValue value =
                i < thread.values.size() ? thread.values[i] : PmuCountValue{};
            if (!value.valid) {
                out += "[unavailable]\n";
                continue;
            }

            out += std::to_string(value.value);
            out += "  enabled=";
            out += format_seconds(value.enabled_ns);
            out += " running=";
            out += format_seconds(value.running_ns);
            if (value.running_ns != 0 &&
                value.running_ns < value.enabled_ns) {
                const uint64_t scaled = static_cast<uint64_t>(
                    static_cast<unsigned __int128>(value.value) *
                    value.enabled_ns / value.running_ns);
                out += "  multiplexed scaled=";
                out += std::to_string(scaled);
            } else if (value.running_ns == 0 && value.enabled_ns != 0) {
                out += "  [not running]";
            }
            out += '\n';
        }
    }
    return out;
}

std::string format_pmu_plan(const std::vector<PmuCounter>& counters,
                            bool sampling, uint64_t sampling_period,
                            int perf_event_paranoid)
{
    std::string out = "PMU counting: ";
    for (size_t i = 0; i < counters.size(); ++i) {
        if (i != 0)
            out += ',';
        out += counters[i].name;
    }
    if (sampling) {
        out += "; sampling every ";
        out += std::to_string(sampling_period);
        out += " events";
    }
    if (perf_event_paranoid >= 0) {
        const char* mode = perf_event_paranoid <= 1
                               ? "kernel+user"
                               : perf_event_paranoid == 2 ? "user-only"
                                                          : "denied";
        out += "; perf_event_paranoid=";
        out += std::to_string(perf_event_paranoid);
        out += " (";
        out += mode;
        out += ')';
    }
    return out;
}

int read_perf_event_paranoid()
{
    std::ifstream input("/proc/sys/kernel/perf_event_paranoid");
    int value = -1;
    if (input >> value)
        return value;
    return -1;
}

}  // namespace callgraph
