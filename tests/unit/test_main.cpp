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
#include "callgraph/histogram_report.h"
#include "callgraph/latency_stats.h"
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

std::vector<std::string> split_lines(const std::string& text)
{
    std::vector<std::string> lines;
    size_t start = 0;
    while (start < text.size()) {
        size_t end = text.find('\n', start);
        if (end == std::string::npos)
            end = text.size();
        lines.push_back(text.substr(start, end - start));
        start = end + 1;
    }
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

void test_errno_string()
{
    CHECK(errno_string(524).find("ENOTSUPP") != std::string::npos);
    CHECK(errno_string(524).find("524") != std::string::npos);
    CHECK(errno_string(-524) == errno_string(524));
    CHECK(errno_string(13) == "Permission denied");

    CHECK(readable_error_message("unknown error (-524)") ==
          "Operation not supported (ENOTSUPP, kernel errno 524)");
    CHECK(readable_error_message("prog 'on_exit': failed: unknown error (-524)") ==
          "prog 'on_exit': failed: Operation not supported "
          "(ENOTSUPP, kernel errno 524)");
    CHECK(readable_error_message("two: unknown error (-524) and (-524)") ==
          "two: Operation not supported (ENOTSUPP, kernel errno 524) and "
          "(-524)");
    CHECK(readable_error_message("nothing to rewrite") ==
          "nothing to rewrite");
    CHECK(readable_error_message("unknown error (") == "unknown error (");
}

void test_latency_histogram()
{
    LatencyHistogram hist;
    hist.add(0);
    hist.add(1);
    hist.add(2);
    hist.add(3);
    hist.add(1000);

    CHECK(hist.calls == 5);
    CHECK(hist.total_ns == 1006);
    CHECK(hist.min_ns == 0);
    CHECK(hist.max_ns == 1000);

    CHECK(latency_bucket(0) == 0);
    CHECK(latency_bucket(1) == 1);
    CHECK(latency_bucket(2) == 2);
    CHECK(latency_bucket(3) == 2);
    CHECK(latency_bucket(1000) == 10);

    CHECK(hist.buckets[0] == 1);
    CHECK(hist.buckets[1] == 1);
    CHECK(hist.buckets[2] == 2);
    CHECK(hist.buckets[10] == 1);
}

void test_histogram_report()
{
    const auto names = make_names();
    const std::string path = temp_path();
    std::string report;

    {
        Output output(path);
        CallStack stack(names, output, -1, false, true);

        stack.on_event(make_event(0, 10, kEventEnter, 1000));
        stack.on_event(make_event(1, 10, kEventEnter, 2000));
        stack.on_event(make_event(1, 10, kEventExit, 5000));
        stack.on_event(make_event(0, 10, kEventExit, 6000));

        stack.on_event(make_event(0, 20, kEventEnter, 1000));
        stack.on_event(make_event(0, 20, kEventExit, 2000));

        stack.finish_statistics();
        report = format_histogram_report(stack.stats(), names);
        output.stop();
    }
    unlink(path.c_str());

    CHECK(report.find("=== thread 10 ===") != std::string::npos);
    CHECK(report.find("=== thread 20 ===") != std::string::npos);
    CHECK(report.find("=== thread 10 ===") < report.find("=== thread 20 ==="));
    CHECK(report.find("main  calls=1") != std::string::npos);
    CHECK(report.find("A(int)  calls=1") != std::string::npos);

    const auto lines = split_lines(report);
    bool checked_alignment = false;
    for (size_t i = 0; i + 1 < lines.size(); ++i) {
        const size_t name_pos = lines[i].find("A(int)  calls=1");
        if (name_pos == std::string::npos)
            continue;

        // A is one level below main, and its bucket line shares that margin.
        CHECK(name_pos == 2);
        const std::string& bucket = lines[i + 1];
        CHECK(bucket.size() > 2);
        CHECK(bucket.compare(0, 2, "  ") == 0);
        CHECK(bucket[2] == '[');
        checked_alignment = true;
        break;
    }
    CHECK(checked_alignment);
}

void test_histogram_incomplete()
{
    const auto names = make_names();
    const std::string path = temp_path();
    std::string report;

    {
        Output output(path);
        CallStack stack(names, output, -1, false, true);

        // main -> A, then main returns: A is skipped and stays incomplete.
        stack.on_event(make_event(0, 30, kEventEnter, 100));
        stack.on_event(make_event(1, 30, kEventEnter, 200));
        stack.on_event(make_event(0, 30, kEventExit, 500));

        // A second thread never returns at all.
        stack.on_event(make_event(2, 31, kEventEnter, 100));

        stack.finish_statistics();
        report = format_histogram_report(stack.stats(), names);
        output.stop();
    }
    unlink(path.c_str());

    CHECK(report.find("=== thread 30 ===") != std::string::npos);
    CHECK(report.find("=== thread 31 ===") != std::string::npos);
    CHECK(report.find("main  calls=1") != std::string::npos);
    CHECK(report.find("A(int)  calls=") == std::string::npos);
    CHECK(report.find("B(int)  calls=0  [incomplete]") != std::string::npos);

    size_t incomplete_lines = 0;
    size_t pos = 0;
    while ((pos = report.find("incomplete: 1 call(s)", pos)) !=
           std::string::npos) {
        ++incomplete_lines;
        ++pos;
    }
    CHECK(incomplete_lines == 2);
}

void test_histogram_live_chain()
{
    const auto names = make_names();
    const std::string path = temp_path();
    std::string report;

    {
        Output output(path);
        CallStack stack(names, output, -1, false, true);

        // main -> A -> B returns while main and A are still live at shutdown.
        stack.on_event(make_event(0, 60, kEventEnter, 100));
        stack.on_event(make_event(1, 60, kEventEnter, 200));
        stack.on_event(make_event(2, 60, kEventEnter, 300));
        stack.on_event(make_event(2, 60, kEventExit, 400));

        stack.finish_statistics();
        report = format_histogram_report(stack.stats(), names);
        output.stop();
    }
    unlink(path.c_str());

    CHECK(report.find("main  calls=0  [incomplete]") != std::string::npos);
    CHECK(report.find("A(int)  calls=0  [incomplete]") != std::string::npos);
    CHECK(report.find("B(int)  calls=1") != std::string::npos);
    CHECK(report.find("incomplete: 2 call(s)") != std::string::npos);

    // B must be nested two levels down: main -> A -> B.
    const size_t b_pos = report.find("B(int)  calls=1");
    CHECK(b_pos != std::string::npos);
    const size_t line_start = report.rfind('\n', b_pos);
    CHECK(line_start != std::string::npos);
    CHECK(b_pos - line_start - 1 == 4);
}

void test_histogram_recursion()
{
    const auto names = make_names();
    const std::string path = temp_path();
    std::string report;

    {
        Output output(path);
        CallStack stack(names, output, -1, false, true);

        stack.on_event(make_event(1, 40, kEventEnter, 0));
        stack.on_event(make_event(1, 40, kEventEnter, 10));
        stack.on_event(make_event(1, 40, kEventExit, 20));
        stack.on_event(make_event(1, 40, kEventExit, 30));

        stack.finish_statistics();
        report = format_histogram_report(stack.stats(), names);
        output.stop();
    }
    unlink(path.c_str());

    size_t markers = 0;
    size_t pos = 0;
    while ((pos = report.find("[recursive]", pos)) != std::string::npos) {
        ++markers;
        ++pos;
    }
    CHECK(markers == 1);
}

void test_histogram_max_depth()
{
    const auto names = make_names();
    const std::string path = temp_path();
    std::string report;

    {
        Output output(path);
        // --max-depth only suppresses event lines; statistics still see A.
        CallStack stack(names, output, 0, false, true);

        stack.on_event(make_event(0, 50, kEventEnter, 0));
        stack.on_event(make_event(1, 50, kEventEnter, 10));
        stack.on_event(make_event(1, 50, kEventExit, 20));
        stack.on_event(make_event(0, 50, kEventExit, 30));

        stack.finish_statistics();
        report = format_histogram_report(stack.stats(), names);
        output.stop();
    }
    unlink(path.c_str());

    CHECK(report.find("main  calls=1") != std::string::npos);
    CHECK(report.find("A(int)  calls=1") != std::string::npos);
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
    test_errno_string();
    test_latency_histogram();
    test_histogram_report();
    test_histogram_incomplete();
    test_histogram_live_chain();
    test_histogram_recursion();
    test_histogram_max_depth();
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
