#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <regex>
#include <string>
#include <vector>

#include <unistd.h>

#include "callgraph/call_stack.h"
#include "callgraph/common.h"
#include "callgraph/event.h"
#include "callgraph/output.h"

using namespace callgraph;

namespace {

int failures = 0;

#define CHECK(condition)                                                       \
    do {                                                                       \
        if (!(condition)) {                                                    \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__,            \
                    #condition);                                               \
            ++failures;                                                        \
        }                                                                      \
    } while (0)

std::string temp_path()
{
    char pattern[] = "/tmp/callgraph-test-XXXXXX";
    const int fd = mkstemp(pattern);
    if (fd >= 0)
        close(fd);
    return pattern;
}

std::vector<std::string> read_lines(const std::string& path)
{
    std::vector<std::string> lines;
    std::ifstream in(path);
    std::string line;
    while (std::getline(in, line))
        lines.push_back(line);
    return lines;
}

TraceEvent make_event(uint64_t function_id, uint32_t tid, uint8_t type,
                      uint64_t ts)
{
    TraceEvent event = {};
    event.func_id = function_id;
    event.tid = tid;
    event.tgid = 1234;
    event.type = type;
    event.ts = ts;
    return event;
}

std::vector<std::string> make_names()
{
    return {"main", "A(int)", "B(int)"};
}

void test_demangle()
{
    CHECK(demangle_symbol("_Z1Ai") == "A(int)");
    CHECK(demangle_symbol("main") == "main");
    CHECK(demangle_symbol("square.constprop.0") == "square.constprop.0");
}

bool looks_like_boot_seconds(const std::string& line)
{
    const auto space = line.find(' ');
    if (space == std::string::npos || space == 0)
        return false;
    const std::string stamp = line.substr(0, space);
    const auto dot = stamp.find('.');
    return dot != std::string::npos && dot > 0 &&
           stamp.size() - dot - 1 == 9;
}

bool looks_like_wall_clock(const std::string& line)
{
    static const std::regex pattern(
        R"(^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{9}[+-][0-9]{2}:[0-9]{2} )");
    return std::regex_search(line, pattern);
}

void test_basic_stack()
{
    const auto names = make_names();
    const std::string path = temp_path();

    {
        Output output(path);
        CallStack stack(names, output, -1, false);

        stack.on_event(make_event(0, 42, kEventEnter, 1));
        stack.on_event(make_event(1, 42, kEventEnter, 2));
        stack.on_event(make_event(1, 42, kEventExit, 3));
        stack.on_event(make_event(0, 42, kEventExit, 4));

        CHECK(stack.entries() == 2);
        CHECK(stack.returns() == 2);
        CHECK(stack.desyncs() == 0);
        CHECK(stack.stray_returns() == 0);
        output.stop();
    }

    const auto lines = read_lines(path);
    CHECK(lines.size() == 4);
    if (lines.size() == 4) {
        CHECK(looks_like_boot_seconds(lines[0]));
        CHECK(lines[0].find(" : 0 -> main") != std::string::npos);
        CHECK(lines[1].find(" : 1 -> A(int)") != std::string::npos);
        CHECK(lines[2].find(" : 1 <- A(int)") != std::string::npos);
        CHECK(lines[3].find(" : 0 <- main") != std::string::npos);
    }
    unlink(path.c_str());
}

void test_wall_clock()
{
    const auto names = make_names();
    const std::string path = temp_path();

    {
        Output output(path, TimestampMode::WallClock);
        CallStack stack(names, output, -1, false);
        stack.on_event(make_event(0, 11, kEventEnter, 1000000000ULL));
        stack.on_event(make_event(0, 11, kEventExit, 2000000000ULL));
        output.stop();
    }

    const auto lines = read_lines(path);
    CHECK(lines.size() == 2);
    if (lines.size() == 2) {
        CHECK(looks_like_wall_clock(lines[0]));
        CHECK(looks_like_wall_clock(lines[1]));
    }
    unlink(path.c_str());
}

void test_indent()
{
    const auto names = make_names();
    const std::string path = temp_path();

    {
        Output output(path, TimestampMode::BootSeconds, 2);
        CallStack stack(names, output, -1, false);
        stack.on_event(make_event(0, 42, kEventEnter, 1));
        stack.on_event(make_event(1, 42, kEventEnter, 2));
        stack.on_event(make_event(2, 42, kEventEnter, 3));
        stack.on_event(make_event(2, 42, kEventExit, 4));
        stack.on_event(make_event(1, 42, kEventExit, 5));
        stack.on_event(make_event(0, 42, kEventExit, 6));
        output.stop();
    }

    const auto lines = read_lines(path);
    CHECK(lines.size() == 6);
    if (lines.size() == 6) {
        CHECK(lines[0].find(" : 0 -> main") != std::string::npos);
        CHECK(lines[1].find(" : 1 ->   A(int)") != std::string::npos);
        CHECK(lines[2].find(" : 2 ->     B(int)") != std::string::npos);
        CHECK(lines[3].find(" : 2 <-     B(int)") != std::string::npos);
        CHECK(lines[4].find(" : 1 <-   A(int)") != std::string::npos);
        CHECK(lines[5].find(" : 0 <- main") != std::string::npos);
    }
    unlink(path.c_str());
}

void test_desync()
{
    const auto names = make_names();
    const std::string path = temp_path();

    {
        Output output(path);
        CallStack stack(names, output, -1, false);

        stack.on_event(make_event(0, 7, kEventEnter, 1));
        stack.on_event(make_event(1, 7, kEventEnter, 2));
        stack.on_event(make_event(2, 7, kEventEnter, 3));
        // main returns without A/B returning: two frames were skipped.
        stack.on_event(make_event(0, 7, kEventExit, 4));

        CHECK(stack.desyncs() == 2);
        CHECK(stack.returns() == 1);
        output.stop();
    }

    const auto lines = read_lines(path);
    CHECK(lines.size() == 4);
    if (lines.size() == 4)
        CHECK(lines[3].find(" : 0 <- main") != std::string::npos);
    unlink(path.c_str());
}

void test_max_depth()
{
    const auto names = make_names();
    const std::string path = temp_path();

    {
        Output output(path);
        CallStack stack(names, output, 0, false);

        stack.on_event(make_event(0, 9, kEventEnter, 1));
        stack.on_event(make_event(1, 9, kEventEnter, 2));
        stack.on_event(make_event(1, 9, kEventExit, 3));
        stack.on_event(make_event(0, 9, kEventExit, 4));

        CHECK(stack.entries() == 2);
        CHECK(stack.returns() == 2);
        output.stop();
    }

    const auto lines = read_lines(path);
    CHECK(lines.size() == 2);
    if (lines.size() == 2) {
        CHECK(lines[0].find(" : 0 -> main") != std::string::npos);
        CHECK(lines[1].find(" : 0 <- main") != std::string::npos);
    }
    unlink(path.c_str());
}

}  // namespace

int main()
{
    test_demangle();
    test_basic_stack();
    test_desync();
    test_max_depth();
    test_wall_clock();
    test_indent();

    if (failures != 0) {
        fprintf(stderr, "%d test(s) failed\n", failures);
        return 1;
    }
    printf("all tests passed\n");
    return 0;
}
