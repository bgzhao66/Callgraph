#include "callgraph/trace_parser.h"

#include <cerrno>
#include <climits>
#include <cmath>
#include <cstdlib>
#include <ctime>
#include <fstream>
#include <regex>
#include <string>

#include "callgraph/call_stack.h"
#include "callgraph/common.h"
#include "callgraph/event.h"
#include "callgraph/trace_metadata.h"

namespace callgraph {
namespace {

bool parse_iso8601(const std::string& text, uint64_t* ns)
{
    int year = 0;
    int month = 0;
    int day = 0;
    int hour = 0;
    int minute = 0;
    int second = 0;
    int nanos = 0;
    char sign = '+';
    int offset_hour = 0;
    int offset_minute = 0;

    const int matched = sscanf(
        text.c_str(), "%4d-%2d-%2dT%2d:%2d:%2d.%9d%c%2d:%2d", &year, &month,
        &day, &hour, &minute, &second, &nanos, &sign, &offset_hour,
        &offset_minute);
    if (matched != 10 || (sign != '+' && sign != '-'))
        return false;

    struct tm local = {};
    local.tm_year = year - 1900;
    local.tm_mon = month - 1;
    local.tm_mday = day;
    local.tm_hour = hour;
    local.tm_min = minute;
    local.tm_sec = second;
    const time_t epoch = timegm(&local);
    if (epoch < 0)
        return false;

    int offset_seconds = offset_hour * 3600 + offset_minute * 60;
    if (sign == '-')
        offset_seconds = -offset_seconds;

    const int64_t value =
        (static_cast<int64_t>(epoch) - offset_seconds) * 1000000000LL +
        nanos;
    if (value < 0)
        return false;
    *ns = static_cast<uint64_t>(value);
    return true;
}

bool parse_boot_seconds(const std::string& text, uint64_t* ns)
{
    const size_t dot = text.find('.');
    if (dot == std::string::npos)
        return false;

    const std::string seconds_text = text.substr(0, dot);
    if (seconds_text.empty())
        return false;

    char* end = nullptr;
    errno = 0;
    const unsigned long long seconds =
        strtoull(seconds_text.c_str(), &end, 10);
    if (errno != 0 || end == seconds_text.c_str() || *end != '\0')
        return false;

    std::string fraction = text.substr(dot + 1);
    if (fraction.size() > 9)
        fraction.resize(9);
    while (fraction.size() < 9)
        fraction.push_back('0');
    const unsigned long long nanos = strtoull(fraction.c_str(), nullptr, 10);
    *ns = static_cast<uint64_t>(seconds) * 1000000000ULL + nanos;
    return true;
}

std::string trim_leading_spaces(std::string value)
{
    const size_t first = value.find_first_not_of(' ');
    if (first == std::string::npos)
        return {};
    value.erase(0, first);
    return value;
}

}  // namespace

TraceParseStats parse_text_trace(
    const std::string& path, CallStack& stack, std::vector<std::string>& names,
    std::vector<FunctionMetadata>& functions,
    const TraceMetadata* metadata, const TraceParseOptions& options,
    uint64_t* last_ts)
{
    TraceParseStats stats;
    *last_ts = 0;

    std::ifstream input(path);
    if (!input)
        fail("cannot open trace %s: %s", path.c_str(),
             errno_string(errno).c_str());

    const std::unordered_map<std::string, FunctionMetadata> meta_by_name =
        metadata ? metadata_by_name(*metadata)
                 : std::unordered_map<std::string, FunctionMetadata>{};

    std::unordered_map<std::string, uint64_t> ids;
    for (size_t i = 0; i < names.size(); ++i)
        ids.emplace(names[i], i);

    const bool have_offset =
        options.have_monotonic_offset ||
        (metadata && metadata->present);
    const uint64_t offset = options.have_monotonic_offset
                                ? options.monotonic_offset_ns
                                : metadata ? metadata->monotonic_offset_ns : 0;

    const std::regex event_re(R"(^(\S+) (\d+) : (\d+) (->|<-) (.*)$)");
    std::string line;
    while (std::getline(input, line)) {
        if (!line.empty() && line.back() == '\r')
            line.pop_back();

        std::smatch match;
        if (!std::regex_match(line, match, event_re)) {
            ++stats.ignored_lines;
            continue;
        }

        const std::string stamp = match[1].str();
        uint64_t ts = 0;
        const bool iso = stamp.find('T') != std::string::npos;
        const bool parsed = iso ? parse_iso8601(stamp, &ts)
                                : parse_boot_seconds(stamp, &ts);
        if (!parsed) {
            ++stats.bad_lines;
            continue;
        }

        if (!iso) {
            if (!have_offset && options.require_timestamp_anchor) {
                fail("trace %s uses monotonic timestamps but no anchor was "
                     "provided; capture with -T, supply --metadata from "
                     "--trace-metadata, or use --assume-local-capture",
                     path.c_str());
            }
            if (have_offset)
                ts += offset;
        }

        char* end = nullptr;
        const std::string tid_text = match[2].str();
        const unsigned long long tid_value =
            strtoull(tid_text.c_str(), &end, 10);
        if (end == tid_text.c_str() || *end != '\0' || tid_value > UINT32_MAX) {
            ++stats.bad_lines;
            continue;
        }
        const uint32_t tid = static_cast<uint32_t>(tid_value);

        const std::string depth_text = match[3].str();
        const unsigned long long depth_value =
            strtoull(depth_text.c_str(), &end, 10);
        if (end == depth_text.c_str() || *end != '\0' ||
            depth_value > static_cast<unsigned long long>(INT_MAX)) {
            ++stats.bad_lines;
            continue;
        }
        const int depth = static_cast<int>(depth_value);

        const bool enter = match[4].str() == "->";

        std::string name = trim_leading_spaces(match[5].str());
        if (name.empty()) {
            ++stats.bad_lines;
            continue;
        }

        // --show-args adds a suffix to entry lines only.  Strip it so entry
        // and return lines map to the same function ID.  Accept both the
        // current `(a=1)` form and the older `[a=1]` form so traces recorded
        // before the format change still replay.  The '=' requirement avoids
        // mistaking a demangled name such as operator()(int) for args.
        std::string arguments;
        if (name.size() > 2 && (name.back() == ')' || name.back() == ']')) {
            const size_t arg_pos =
                name.rfind(name.back() == ')' ? " (" : " [");
            if (arg_pos != std::string::npos &&
                name.find('=', arg_pos) != std::string::npos) {
                arguments = name.substr(arg_pos + 1);
                name.resize(arg_pos);
            }
        }

        auto [id_it, inserted] = ids.emplace(name, names.size());
        if (inserted) {
            names.push_back(name);
            auto meta_it = meta_by_name.find(name);
            if (meta_it != meta_by_name.end()) {
                functions.push_back(meta_it->second);
            } else {
                FunctionMetadata function;
                function.name = name;
                function.linkage_name = name;
                functions.push_back(std::move(function));
            }
        }

        TraceEvent event = {};
        event.ts = ts;
        event.tid = tid;
        event.tgid = 0;
        event.func_id = id_it->second;
        event.type = enter ? kEventEnter : kEventExit;
        stack.on_event(event,
                       options.input_show_args ? arguments : std::string{},
                       depth);

        *last_ts = ts;
        ++stats.event_lines;
        if (enter)
            ++stats.entries;
        else
            ++stats.exits;
    }

    return stats;
}

}  // namespace callgraph
