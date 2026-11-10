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

ParameterInfo make_parameter(const std::string& name, ArgumentKind kind,
                             uint32_t size, bool is_signed = false)
{
    ParameterInfo parameter;
    parameter.name = name;
    parameter.kind = kind;
    parameter.byte_size = size;
    parameter.is_signed = is_signed;
    return parameter;
}

void test_argument_formatting()
{
    FunctionSignature signature;
    signature.has_signature = true;
    signature.parameters.push_back(
        make_parameter("x", ArgumentKind::Integer, 4, true));
    signature.parameters.push_back(
        make_parameter("p", ArgumentKind::Pointer, 8));
    signature.parameters.push_back(
        make_parameter("flag", ArgumentKind::Boolean, 1));
    signature.parameters.push_back(
        make_parameter("ch", ArgumentKind::Char, 1, true));
    classify_parameters(signature);

    TraceEvent event = {};
    event.args[0] = 3;
    event.args[1] = 0x1234;
    event.args[2] = 1;
    event.args[3] = 'A';

    CHECK(format_arguments(signature, event) ==
          " [x=3, p=0x1234, flag=true, ch='A']");
}

void test_argument_signedness()
{
    FunctionSignature signature;
    signature.has_signature = true;
    signature.parameters.push_back(
        make_parameter("x", ArgumentKind::Integer, 4, true));
    classify_parameters(signature);

    TraceEvent event = {};
    event.args[0] = 0xfffffffeu;
    CHECK(format_arguments(signature, event) == " [x=-2]");

    signature.parameters[0].is_signed = false;
    CHECK(format_arguments(signature, event) == " [x=4294967294]");
}

void test_argument_stack()
{
    FunctionSignature signature;
    signature.has_signature = true;
    for (int i = 0; i < 7; ++i)
        signature.parameters.push_back(
            make_parameter("a" + std::to_string(i), ArgumentKind::Integer, 4,
                           true));
    classify_parameters(signature);

    TraceEvent event = {};
    for (int i = 0; i < 6; ++i)
        event.args[i] = static_cast<uint64_t>(i + 1);
    event.stack[0] = 7;

    CHECK(format_arguments(signature, event) ==
          " [a0=1, a1=2, a2=3, a3=4, a4=5, a5=6, a6=7]");
}

void test_argument_artificial()
{
    FunctionSignature signature;
    signature.has_signature = true;

    ParameterInfo self = make_parameter("this", ArgumentKind::Pointer, 8);
    self.artificial = true;
    signature.parameters.push_back(self);
    signature.parameters.push_back(
        make_parameter("x", ArgumentKind::Integer, 4, true));
    classify_parameters(signature);

    TraceEvent event = {};
    event.args[0] = 0xdeadbeef;
    event.args[1] = 9;

    CHECK(format_arguments(signature, event) == " [x=9]");
}

void test_argument_aggregate()
{
    FunctionSignature signature;
    signature.has_signature = true;
    ParameterInfo aggregate = make_parameter("s", ArgumentKind::Aggregate, 16);
    signature.parameters.push_back(aggregate);
    classify_parameters(signature);

    TraceEvent event = {};
    event.args[0] = 1;
    event.args[1] = 2;
    CHECK(format_arguments(signature, event) == " [s={0x1, 0x2}]");

    signature.parameters[0].contains_float = true;
    classify_parameters(signature);
    CHECK(format_arguments(signature, event) == " [s=?]");
}

void test_argument_stack_float()
{
    FunctionSignature signature;
    signature.has_signature = true;
    for (int i = 0; i < 9; ++i)
        signature.parameters.push_back(
            make_parameter("f" + std::to_string(i), ArgumentKind::Float, 8));
    classify_parameters(signature);

    TraceEvent event = {};
    // 2.5 as an IEEE-754 double.
    event.stack[0] = 0x4004000000000000ULL;

    const std::string rendered = format_arguments(signature, event);
    CHECK(rendered.find("f8=2.5") != std::string::npos);
    CHECK(rendered.find("f0=?") != std::string::npos);
}

void test_call_stack_arguments()
{
    const std::vector<std::string> names = {"foo"};
    FunctionSignature signature;
    signature.has_signature = true;
    signature.parameters.push_back(
        make_parameter("x", ArgumentKind::Integer, 4, true));
    classify_parameters(signature);
    const std::vector<FunctionSignature> signatures = {signature};

    const std::string path = temp_path();
    {
        Output output(path);
        CallStack stack(names, &signatures, output, -1, false);

        TraceEvent enter = make_event(0, 5, kEventEnter, 1);
        enter.args[0] = 42;
        stack.on_event(enter);
        stack.on_event(make_event(0, 5, kEventExit, 2));
        output.stop();
    }

    const auto lines = read_lines(path);
    CHECK(lines.size() == 2);
    if (lines.size() == 2) {
        CHECK(lines[0].find(" : 0 -> foo [x=42]") != std::string::npos);
        CHECK(lines[1].find(" : 0 <- foo") != std::string::npos);
        CHECK(lines[1].find("[x=42]") == std::string::npos);
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
    test_argument_formatting();
    test_argument_signedness();
    test_argument_stack();
    test_argument_artificial();
    test_argument_aggregate();
    test_argument_stack_float();
    test_call_stack_arguments();

    if (failures != 0) {
        fprintf(stderr, "%d test(s) failed\n", failures);
        return 1;
    }
    printf("all tests passed\n");
    return 0;
}
