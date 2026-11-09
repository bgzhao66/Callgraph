#include <cstdio>
#include <cstdlib>
#include <fstream>
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
        CHECK(lines[0].find(" : 0 -> main") != std::string::npos);
        CHECK(lines[1].find(" : 1 -> A(int)") != std::string::npos);
        CHECK(lines[2].find(" : 1 <- A(int)") != std::string::npos);
        CHECK(lines[3].find(" : 0 <- main") != std::string::npos);
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

    if (failures != 0) {
        fprintf(stderr, "%d test(s) failed\n", failures);
        return 1;
    }
    printf("all tests passed\n");
    return 0;
}
