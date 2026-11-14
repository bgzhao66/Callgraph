#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <fstream>
#include <iterator>
#include <regex>
#include <string>
#include <unordered_map>
#include <vector>

#include <unistd.h>

#include "callgraph/call_stack.h"
#include "callgraph/common.h"
#include "callgraph/event.h"
#include "callgraph/flame_graph.h"
#include "callgraph/histogram_report.h"
#include "callgraph/kernel_event.h"
#include "callgraph/kernel_timeline.h"
#include "callgraph/latency_stats.h"
#include "callgraph/otel_exporter.h"
#include "callgraph/otlp_json.h"
#include "callgraph/otlp_proto.h"
#include "callgraph/output.h"
#include "callgraph/span_generator.h"
#include "callgraph/clock_converter.h"
#include "callgraph/trace_metadata.h"
#include "callgraph/trace_parser.h"

#ifdef CALLGRAPH_HAVE_OTLP_PROTO
#include "opentelemetry/proto/collector/trace/v1/trace_service.pb.h"
#endif

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

std::string read_file(const std::string& path)
{
    std::ifstream in(path);
    return std::string(std::istreambuf_iterator<char>(in),
                       std::istreambuf_iterator<char>());
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

// Histogram entries start with a bar line whose length depends on the root
// duration.  Assertions about the heading/summary adjacency ignore it.
std::string without_histogram_bars(const std::string& report)
{
    std::string out;
    size_t pos = 0;
    while (pos < report.size()) {
        const size_t end = report.find('\n', pos);
        const size_t line_end = end == std::string::npos ? report.size() : end;
        const std::string line = report.substr(pos, line_end - pos);
        const bool is_bar =
            line.size() > 3 && line.compare(0, 3, "   ") == 0 &&
            line.find_first_not_of('-', 3) == std::string::npos;
        if (!is_bar) {
            out += line;
            out += '\n';
        }
        if (end == std::string::npos)
            break;
        pos = end + 1;
    }
    return out;
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
    CHECK(report.find("Tree:") != std::string::npos);
    CHECK(report.find("Histograms:") != std::string::npos);
    CHECK(report.find("Tree:") < report.find("Histograms:"));
    CHECK(without_histogram_bars(report).find("0. main\n   calls=1") !=
          std::string::npos);
    CHECK(without_histogram_bars(report).find("1. A(int)\n   calls=1") !=
          std::string::npos);
    // Tree nodes end with their inclusive edge total, joined to the label by a
    // middle-dot leader and aligned in per-unit columns.
    CHECK(report.find("main······· 5.00us") != std::string::npos);
    CHECK(report.find("└── A(int)· 3.00us") != std::string::npos);
    CHECK(report.find("└── A(int)  calls=") == std::string::npos);
    CHECK(report.find("\n   [ ") != std::string::npos);
    // The bar sits under the heading and measures the function's share of the
    // root span: main fills it, A is 3000/5000 of main.
    CHECK(report.find("0. main\n   ----------------------------------------\n"
                      "   calls=1") != std::string::npos);
    CHECK(report.find("1. A(int)\n   ------------------------\n"
                      "   calls=1") != std::string::npos);
}

void test_histogram_bar_proportional()
{
    const auto names = make_names();
    const std::string path = temp_path();
    std::string report;

    {
        Output output(path);
        CallStack stack(names, output, -1, false, true);

        // Root span lasts 800 ns.  A is called twice at depth 1 for 100 ns and
        // 200 ns, so its aggregated entry is 300 ns: 300/800 of the root.
        stack.on_event(make_event(0, 10, kEventEnter, 0));
        stack.on_event(make_event(1, 10, kEventEnter, 100));
        stack.on_event(make_event(1, 10, kEventExit, 200));
        stack.on_event(make_event(1, 10, kEventEnter, 300));
        stack.on_event(make_event(1, 10, kEventExit, 500));
        stack.on_event(make_event(0, 10, kEventExit, 800));

        stack.finish_statistics();
        report = format_histogram_report(stack.stats(), names);
        output.stop();
    }
    unlink(path.c_str());

    CHECK(report.find("0. main\n   ----------------------------------------\n"
                      "   calls=1") != std::string::npos);
    // 300/800 * 40 = 15 dashes; both latency buckets share this one bar.
    CHECK(report.find("1. A(int)\n   ---------------\n"
                      "   calls=2") != std::string::npos);
    // Tree nodes carry the same inclusive totals, aligned in per-unit columns.
    CHECK(report.find("main······· 800ns") != std::string::npos);
    CHECK(report.find("└── A(int)· 300ns") != std::string::npos);

    size_t bars = 0;
    size_t pos = 0;
    while ((pos = report.find("\n   --", pos)) != std::string::npos) {
        ++bars;
        ++pos;
    }
    CHECK(bars == 2);
}

void test_histogram_tree_units()
{
    const auto names = make_names();
    const std::string path = temp_path();
    std::string report;

    {
        Output output(path);
        CallStack stack(names, output, -1, false, true);

        // Root lasts 8.4 ms but its child is only 100 ns.  A tree-wide unit
        // would round the child down to 0.00ms.
        stack.on_event(make_event(0, 90, kEventEnter, 0));
        stack.on_event(make_event(1, 90, kEventEnter, 0));
        stack.on_event(make_event(1, 90, kEventExit, 100));
        stack.on_event(make_event(0, 90, kEventExit, 8400000));

        stack.finish_statistics();
        report = format_histogram_report(stack.stats(), names);
        output.stop();
    }
    unlink(path.c_str());

    CHECK(report.find("main······· 8.40ms") != std::string::npos);
    // Each unit has its own column, so the finer ns value is indented past the
    // ms column instead of sharing its right edge.
    CHECK(report.find("└── A(int)······· 100ns") != std::string::npos);
    // The long root must not force a coarser unit on the short child.
    CHECK(report.find("0.00ms") == std::string::npos);
}

void test_histogram_tree_unit_columns()
{
    const auto names = make_names();
    const std::string path = temp_path();
    std::string report;

    {
        Output output(path);
        CallStack stack(names, output, -1, false, true);

        // Same-unit nodes must share a column even when the numbers differ in
        // width, and a finer unit is indented past the coarser column.
        stack.on_event(make_event(0, 91, kEventEnter, 0));
        stack.on_event(make_event(1, 91, kEventEnter, 0));
        stack.on_event(make_event(2, 91, kEventEnter, 100));
        stack.on_event(make_event(2, 91, kEventExit, 900));        // 800ns
        stack.on_event(make_event(1, 91, kEventExit, 10000000));   // 10.00ms
        stack.on_event(make_event(0, 91, kEventExit, 20000000));   // 20.00ms

        stack.finish_statistics();
        report = format_histogram_report(stack.stats(), names);
        output.stop();
    }
    unlink(path.c_str());

    // Equal units share a column, so the two ms values start at the same
    // display column; the finer ns value is indented past the ms column.
    CHECK(report.find("main··········· 20.00ms") != std::string::npos);
    CHECK(report.find("└── A(int)····· 10.00ms") != std::string::npos);
    CHECK(report.find("    └── B(int)········ 800ns") != std::string::npos);
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
    CHECK(without_histogram_bars(report).find("0. main\n   calls=1") !=
          std::string::npos);
    CHECK(report.find("A(int)  calls=") == std::string::npos);
    CHECK(report.find("0. B(int)  [incomplete]\n   calls=0  [incomplete]") !=
          std::string::npos);

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

    CHECK(report.find("0. main  [incomplete]\n   calls=0  [incomplete]") !=
          std::string::npos);
    CHECK(report.find("1. A(int)  [incomplete]\n   calls=0") !=
          std::string::npos);
    CHECK(without_histogram_bars(report).find("2. B(int)\n   calls=1") !=
          std::string::npos);
    CHECK(report.find("incomplete: 2 call(s)") != std::string::npos);

    // B must be nested two levels down in the tree: main -> A -> B.  The live
    // main/A frames have no measured total, so only B carries a time; check
    // that the padded tree line ends with it.
    CHECK(std::regex_search(report,
                            std::regex("    └── B\\(int\\).* 100ns")));
    CHECK(report.find("    └── B(int)  calls=") == std::string::npos);
}

void test_histogram_siblings()
{
    const auto names = make_names();
    const std::string path = temp_path();
    std::string report;

    {
        Output output(path);
        CallStack stack(names, output, -1, false, true);

        stack.on_event(make_event(0, 70, kEventEnter, 0));
        stack.on_event(make_event(1, 70, kEventEnter, 10));
        stack.on_event(make_event(1, 70, kEventExit, 110));  // A: 100 ns
        stack.on_event(make_event(2, 70, kEventEnter, 120));
        stack.on_event(make_event(2, 70, kEventExit, 420));  // B: 300 ns
        stack.on_event(make_event(0, 70, kEventExit, 430));

        stack.finish_statistics();
        report = format_histogram_report(stack.stats(), names);
        output.stop();
    }
    unlink(path.c_str());

    // Siblings follow call order (A occurred before B), not duration.
    CHECK(report.find("├── A(int)· 100ns") != std::string::npos);
    CHECK(report.find("└── B(int)· 300ns") != std::string::npos);
    CHECK(report.find("├── A(int)  calls=") == std::string::npos);
    CHECK(report.find("└── B(int)  calls=") == std::string::npos);
    CHECK(without_histogram_bars(report).find("1. A(int)\n   calls=1") !=
          std::string::npos);
    CHECK(without_histogram_bars(report).find("1. B(int)\n   calls=1") !=
          std::string::npos);
    // Histogram order follows the tree, even though B was slower.
    CHECK(report.find("1. A(int)") < report.find("1. B(int)"));
}

void test_histogram_roots()
{
    const auto names = make_names();
    const std::string path = temp_path();
    std::string report;

    {
        Output output(path);
        CallStack stack(names, output, -1, false, true);

        // Two independent root calls in the same thread.
        stack.on_event(make_event(1, 80, kEventEnter, 0));
        stack.on_event(make_event(1, 80, kEventExit, 200));   // A: 200 ns
        stack.on_event(make_event(2, 80, kEventEnter, 300));
        stack.on_event(make_event(2, 80, kEventExit, 400));   // B: 100 ns

        stack.finish_statistics();
        report = format_histogram_report(stack.stats(), names);
        output.stop();
    }
    unlink(path.c_str());

    CHECK(without_histogram_bars(report).find("0. A(int)\n   calls=1") !=
          std::string::npos);
    CHECK(without_histogram_bars(report).find("0. B(int)\n   calls=1") !=
          std::string::npos);
    // Roots are emitted in call order: A occurred before B.
    CHECK(report.find("0. A(int)") < report.find("0. B(int)"));

    // Each root is a Tree/Histograms pair, emitted in root order, so the
    // second tree starts after the first root's histograms.
    const size_t first_tree = report.find("Tree:");
    const size_t first_hist = report.find("Histograms:");
    const size_t second_tree = report.find("Tree:", first_tree + 1);
    const size_t second_hist = report.find("Histograms:", first_hist + 1);
    CHECK(first_tree != std::string::npos);
    CHECK(first_hist != std::string::npos);
    CHECK(second_tree != std::string::npos);
    CHECK(second_hist != std::string::npos);
    CHECK(first_tree < first_hist);
    CHECK(first_hist < second_tree);
    CHECK(second_tree < second_hist);
    CHECK(report.find("0. A(int)") < second_tree);
    CHECK(report.find("0. B(int)") > second_tree);
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
    CHECK(markers == 2);
    CHECK(without_histogram_bars(report)
              .find("1. A(int)  [recursive]\n   calls=1") !=
          std::string::npos);
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

    CHECK(without_histogram_bars(report).find("0. main\n   calls=1") !=
          std::string::npos);
    CHECK(without_histogram_bars(report).find("1. A(int)\n   calls=1") !=
          std::string::npos);
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
          " (x=3, p=0x1234, flag=true, ch='A')");
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
    CHECK(format_arguments(signature, event) == " (x=-2)");

    signature.parameters[0].is_signed = false;
    CHECK(format_arguments(signature, event) == " (x=4294967294)");
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
          " (a0=1, a1=2, a2=3, a3=4, a4=5, a5=6, a6=7)");
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

    CHECK(format_arguments(signature, event) == " (x=9)");
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
    CHECK(format_arguments(signature, event) == " (s={0x1, 0x2})");

    signature.parameters[0].contains_float = true;
    classify_parameters(signature);
    CHECK(format_arguments(signature, event) == " (s=?)");
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
        CHECK(lines[0].find(" : 0 -> foo (x=42)") != std::string::npos);
        CHECK(lines[1].find(" : 0 <- foo") != std::string::npos);
        CHECK(lines[1].find("(x=42)") == std::string::npos);
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

void test_sp_unwind_on_enter()
{
    const auto names = make_names();

    // Normal nesting: each callee enters at a lower rsp, so nothing is dropped.
    {
        const std::string path = temp_path();
        Output output(path);
        CallStack stack(names, output, -1, false);

        TraceEvent main_enter = make_event(0, 8, kEventEnter, 1);
        main_enter.sp = 0x7f000;
        TraceEvent a_enter = make_event(1, 8, kEventEnter, 2);
        a_enter.sp = 0x6ff0;
        TraceEvent b_enter = make_event(2, 8, kEventEnter, 3);
        b_enter.sp = 0x6fe0;

        stack.on_event(main_enter);
        stack.on_event(a_enter);
        stack.on_event(b_enter);
        CHECK(stack.desyncs() == 0);
        CHECK(stack.live_threads() == 1);

        stack.on_event(make_event(2, 8, kEventExit, 4));
        stack.on_event(make_event(1, 8, kEventExit, 5));
        stack.on_event(make_event(0, 8, kEventExit, 6));
        CHECK(stack.desyncs() == 0);
        CHECK(stack.returns() == 3);
        CHECK(stack.live_threads() == 0);
        output.stop();
        unlink(path.c_str());
    }

    // longjmp back to main, then main calls A again from the same site.  The
    // stale A and B are below the new call site, so both must be dropped and
    // the new A must start at depth 1.
    {
        const std::string path = temp_path();
        Output output(path);
        CallStack stack(names, output, -1, false);

        TraceEvent main_enter = make_event(0, 9, kEventEnter, 1);
        main_enter.sp = 0x7f000;
        TraceEvent a_enter = make_event(1, 9, kEventEnter, 2);
        a_enter.sp = 0x6ff0;
        TraceEvent b_enter = make_event(2, 9, kEventEnter, 3);
        b_enter.sp = 0x6fe0;
        TraceEvent a_again = make_event(1, 9, kEventEnter, 4);
        a_again.sp = 0x6ff0;

        stack.on_event(main_enter);
        stack.on_event(a_enter);
        stack.on_event(b_enter);
        stack.on_event(a_again);

        CHECK(stack.desyncs() == 2);
        CHECK(stack.entries() == 4);

        stack.on_event(make_event(1, 9, kEventExit, 5));
        stack.on_event(make_event(0, 9, kEventExit, 6));
        CHECK(stack.returns() == 2);
        CHECK(stack.live_threads() == 0);
        output.stop();

        const auto lines = read_lines(path);
        CHECK(lines.size() == 6);
        if (lines.size() == 6) {
            CHECK(lines[0].find(" : 0 -> main") != std::string::npos);
            CHECK(lines[1].find(" : 1 -> A(int)") != std::string::npos);
            CHECK(lines[2].find(" : 2 -> B(int)") != std::string::npos);
            CHECK(lines[3].find(" : 1 -> A(int)") != std::string::npos);
            CHECK(lines[4].find(" : 1 <- A(int)") != std::string::npos);
            CHECK(lines[5].find(" : 0 <- main") != std::string::npos);
        }
        unlink(path.c_str());
    }

    // Offline text traces carry sp == 0 and must not be pruned.
    {
        const std::string path = temp_path();
        Output output(path);
        CallStack stack(names, output, -1, false);
        stack.on_event(make_event(0, 10, kEventEnter, 1));
        stack.on_event(make_event(1, 10, kEventEnter, 2));
        stack.on_event(make_event(2, 10, kEventEnter, 3));
        CHECK(stack.desyncs() == 0);
        CHECK(stack.live_threads() == 1);
        output.stop();
        unlink(path.c_str());
    }
}

// A stackful runtime switches to an unrelated stack.  With resync on, the
// suspended frames look unwound; with --no-rsp-resync they are kept and their
// returns still pair up.
void test_no_rsp_resync()
{
    const auto names = make_names();

    // Default: the higher stack makes the suspended frame look unwound.
    {
        const std::string path = temp_path();
        Output output(path);
        CallStack stack(names, output, -1, false);

        TraceEvent main_enter = make_event(0, 11, kEventEnter, 1);
        main_enter.sp = 0x7f000;
        TraceEvent a_enter = make_event(1, 11, kEventEnter, 2);
        a_enter.sp = 0x6ff0;
        TraceEvent b_enter = make_event(2, 11, kEventEnter, 3);
        b_enter.sp = 0x9000;

        stack.on_event(main_enter);
        stack.on_event(a_enter);
        stack.on_event(b_enter);

        CHECK(stack.desyncs() == 1);
        CHECK(stack.entries() == 3);
        output.stop();
        unlink(path.c_str());
    }

    // Disabled: A survives the switch, B nests below it, and every return
    // matches by searching down the stack.
    {
        const std::string path = temp_path();
        Output output(path);
        CallStack stack(names, output, -1, false);
        stack.set_rsp_resync(false);

        TraceEvent main_enter = make_event(0, 12, kEventEnter, 1);
        main_enter.sp = 0x7f000;
        TraceEvent a_enter = make_event(1, 12, kEventEnter, 2);
        a_enter.sp = 0x6ff0;
        TraceEvent b_enter = make_event(2, 12, kEventEnter, 3);
        b_enter.sp = 0x9000;

        stack.on_event(main_enter);
        stack.on_event(a_enter);
        stack.on_event(b_enter);
        CHECK(stack.desyncs() == 0);
        CHECK(stack.entries() == 3);

        stack.on_event(make_event(2, 12, kEventExit, 4));
        stack.on_event(make_event(1, 12, kEventExit, 5));
        stack.on_event(make_event(0, 12, kEventExit, 6));
        CHECK(stack.desyncs() == 0);
        CHECK(stack.stray_returns() == 0);
        CHECK(stack.returns() == 3);
        CHECK(stack.live_threads() == 0);
        output.stop();

        const auto lines = read_lines(path);
        CHECK(lines.size() == 6);
        if (lines.size() == 6) {
            CHECK(lines[2].find(" : 2 -> B(int)") != std::string::npos);
            CHECK(lines[4].find(" : 1 <- A(int)") != std::string::npos);
        }
        unlink(path.c_str());
    }
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

void test_span_generator()
{
    const std::vector<std::string> names = {"main", "A(int)", "B(int)"};
    std::vector<FunctionMetadata> functions;
    for (const auto& name : names) {
        FunctionMetadata metadata;
        metadata.name = name;
        metadata.linkage_name = name;
        metadata.module_path = "/tmp/app";
        metadata.file_offset = 0x1234;
        functions.push_back(metadata);
    }

    SpanGeneratorConfig config;
    config.scope = TraceScope::Root;
    config.seed_hi = 11;
    config.seed_lo = 22;
    config.timestamps_are_unix = true;
    config.functions = &functions;

    std::vector<SpanRecord> closed;
    SpanGenerator builder(config, [&](SpanRecord&& span) {
        closed.push_back(std::move(span));
    });
    CallStack stack(names, static_cast<Output*>(nullptr), -1, false, false,
                    &builder);

    stack.on_event(make_event(0, 10, kEventEnter, 1000));
    stack.on_event(make_event(1, 10, kEventEnter, 2000));
    stack.on_event(make_event(1, 10, kEventExit, 3000));
    stack.on_event(make_event(0, 10, kEventExit, 4000));

    CHECK(closed.size() == 2);
    if (closed.size() == 2) {
        const SpanRecord& a = closed[0];
        const SpanRecord& main = closed[1];
        CHECK(a.function.name == "A(int)");
        CHECK(main.function.name == "main");
        CHECK(a.context.parent_span_id == main.context.span_id);
        CHECK(main.context.parent_span_id == 0);
        CHECK(a.depth == 1);
        CHECK(a.start_unix_ns == 2000);
        CHECK(a.end_unix_ns == 3000);
        CHECK(!a.incomplete);
        CHECK(a.context.trace_id == main.context.trace_id);
    }

    // A skipped return closes the intervening frames as incomplete.
    std::vector<SpanRecord> desynced;
    SpanGenerator desync_builder(config, [&](SpanRecord&& span) {
        desynced.push_back(std::move(span));
    });
    CallStack desync_stack(names, static_cast<Output*>(nullptr), -1, false,
                           false, &desync_builder);
    desync_stack.on_event(make_event(0, 11, kEventEnter, 100));
    desync_stack.on_event(make_event(1, 11, kEventEnter, 200));
    desync_stack.on_event(make_event(2, 11, kEventEnter, 300));
    desync_stack.on_event(make_event(0, 11, kEventExit, 400));

    CHECK(desynced.size() == 3);
    if (desynced.size() == 3) {
        CHECK(desynced[0].function.name == "B(int)");
        CHECK(desynced[0].incomplete);
        CHECK(desynced[0].reason == SpanCloseReason::Desync);
        CHECK(desynced[0].end_unix_ns == 400);
        CHECK(desynced[1].function.name == "A(int)");
        CHECK(desynced[1].incomplete);
        CHECK(desynced[2].function.name == "main");
        CHECK(!desynced[2].incomplete);
    }

    // Frames still live at shutdown are closed once.
    std::vector<SpanRecord> live;
    SpanGenerator live_builder(config, [&](SpanRecord&& span) {
        live.push_back(std::move(span));
    });
    CallStack live_stack(names, static_cast<Output*>(nullptr), -1, false,
                         false, &live_builder);
    live_stack.on_event(make_event(0, 12, kEventEnter, 100));
    live_stack.on_event(make_event(1, 12, kEventEnter, 200));
    live_stack.finish_spans(500);
    live_stack.finish_spans(600);

    CHECK(live.size() == 2);
    if (live.size() == 2) {
        CHECK(live[0].function.name == "A(int)");
        CHECK(live[0].incomplete);
        CHECK(live[0].end_unix_ns == 500);
        CHECK(live[1].function.name == "main");
        CHECK(live[1].incomplete);
        CHECK(live[1].end_unix_ns == 500);
    }
}

void test_span_unwind_on_enter()
{
    const std::vector<std::string> names = {"main", "A(int)", "B(int)"};
    std::vector<FunctionMetadata> functions;
    for (const auto& name : names) {
        FunctionMetadata metadata;
        metadata.name = name;
        functions.push_back(metadata);
    }

    SpanGeneratorConfig config;
    config.scope = TraceScope::Root;
    config.seed_hi = 1;
    config.seed_lo = 2;
    config.timestamps_are_unix = true;
    config.functions = &functions;

    std::vector<SpanRecord> closed;
    SpanGenerator builder(config, [&](SpanRecord&& span) {
        closed.push_back(std::move(span));
    });
    CallStack stack(names, static_cast<Output*>(nullptr), -1, false, false,
                    &builder);

    TraceEvent main_enter = make_event(0, 13, kEventEnter, 100);
    main_enter.sp = 0x7f000;
    TraceEvent a_enter = make_event(1, 13, kEventEnter, 200);
    a_enter.sp = 0x6ff0;
    TraceEvent b_enter = make_event(2, 13, kEventEnter, 300);
    b_enter.sp = 0x6fe0;
    TraceEvent a_again = make_event(1, 13, kEventEnter, 400);
    a_again.sp = 0x6ff0;

    stack.on_event(main_enter);
    stack.on_event(a_enter);
    stack.on_event(b_enter);
    stack.on_event(a_again);  // unwinds B and the stale A
    stack.on_event(make_event(1, 13, kEventExit, 500));
    stack.on_event(make_event(0, 13, kEventExit, 600));

    CHECK(closed.size() == 4);
    if (closed.size() == 4) {
        CHECK(closed[0].function.name == "B(int)");
        CHECK(closed[0].incomplete);
        CHECK(closed[0].reason == SpanCloseReason::Desync);
        CHECK(closed[0].end_unix_ns == 400);
        CHECK(closed[1].function.name == "A(int)");
        CHECK(closed[1].incomplete);
        CHECK(closed[1].reason == SpanCloseReason::Desync);
        CHECK(closed[2].function.name == "A(int)");
        CHECK(!closed[2].incomplete);
        CHECK(closed[2].reason == SpanCloseReason::Return);
        CHECK(closed[2].end_unix_ns == 500);
        CHECK(closed[3].function.name == "main");
        CHECK(closed[3].reason == SpanCloseReason::Return);
    }
}

void test_span_trace_scope()
{
    const std::vector<std::string> names = {"main"};
    std::vector<FunctionMetadata> functions;
    FunctionMetadata metadata;
    metadata.name = "main";
    functions.push_back(metadata);

    const auto collect = [&](TraceScope scope) {
        SpanGeneratorConfig config;
        config.scope = scope;
        config.seed_hi = 1;
        config.seed_lo = 2;
        config.timestamps_are_unix = true;
        config.functions = &functions;
        std::vector<SpanRecord> spans;
        SpanGenerator builder(config, [&](SpanRecord&& span) {
            spans.push_back(std::move(span));
        });
        CallStack stack(names, static_cast<Output*>(nullptr), -1, false, false,
                        &builder);
        stack.on_event(make_event(0, 20, kEventEnter, 100));
        stack.on_event(make_event(0, 20, kEventExit, 200));
        stack.on_event(make_event(0, 20, kEventEnter, 300));
        stack.on_event(make_event(0, 20, kEventExit, 400));
        return spans;
    };

    const auto root = collect(TraceScope::Root);
    CHECK(root.size() == 2);
    if (root.size() == 2)
        CHECK(root[0].context.trace_id != root[1].context.trace_id);

    const auto thread = collect(TraceScope::Thread);
    CHECK(thread.size() == 2);
    if (thread.size() == 2)
        CHECK(thread[0].context.trace_id == thread[1].context.trace_id);
}

void test_otlp_encoding()
{
    SpanRecord span;
    span.context.trace_id[15] = 1;
    span.context.span_id = 0x1234;
    span.function_id = 7;
    span.tid = 42;
    span.depth = 2;
    span.start_unix_ns = 1000;
    span.end_unix_ns = 2000;
    span.function.name = "A\"\\B";
    span.function.linkage_name = "_Z1Av";
    span.function.module_path = "/tmp/app";
    span.function.file_offset = 0x99;
    span.function.source_file = "/tmp/app.cpp";
    span.function.source_line = 17;
    span.thread_name = "worker-1";

    OtelConfig config;
    config.service_name = "demo";
    config.pid = 123;
    config.return_mode = "uretprobe";
    config.trace_scope = "root";
    config.tool_version = "0.1.0";

    const std::string json = encode_otlp_request({span}, config);
    CHECK(json.find("\"resourceSpans\"") != std::string::npos);
    CHECK(json.find("\"scopeSpans\"") != std::string::npos);
    CHECK(json.find("\"traceId\":\"00000000000000000000000000000001\"") !=
          std::string::npos);
    CHECK(json.find("\"spanId\":\"0000000000001234\"") != std::string::npos);
    CHECK(json.find("\"name\":\"A\\\"\\\\B\"") != std::string::npos);
    CHECK(json.find("\"parentSpanId\"") == std::string::npos);
    CHECK(json.find("{{") == std::string::npos);
    CHECK(json.find("\"key\":\"thread.id\"") != std::string::npos);
    CHECK(json.find("\"key\":\"thread.name\"") != std::string::npos);
    CHECK(json.find("\"key\":\"code.function\"") != std::string::npos);
    CHECK(json.find("\"key\":\"code.filepath\"") != std::string::npos);
    CHECK(json.find("\"key\":\"code.lineno\"") != std::string::npos);
    CHECK(json.find("\"key\":\"callgraph.module\"") != std::string::npos);

    if (otlp_protobuf_available()) {
        const std::string protobuf = encode_otlp_protobuf({span}, config);
        CHECK(!protobuf.empty());
#ifdef CALLGRAPH_HAVE_OTLP_PROTO
        opentelemetry::proto::collector::trace::v1::
            ExportTraceServiceRequest request;
        CHECK(request.ParseFromString(protobuf));
        CHECK(request.resource_spans_size() == 1);
        CHECK(request.resource_spans(0).scope_spans_size() == 1);
        CHECK(request.resource_spans(0).scope_spans(0).spans_size() == 1);
        const auto& encoded_span =
            request.resource_spans(0).scope_spans(0).spans(0);
        CHECK(encoded_span.name() == "A\"\\B");
        CHECK(encoded_span.trace_id().size() == 16);
        CHECK(encoded_span.span_id().size() == 8);
#endif
    }
}

void test_root_sampling()
{
    const std::vector<std::string> names = {"main", "A(int)"};
    std::vector<FunctionMetadata> functions;
    for (const auto& name : names) {
        FunctionMetadata metadata;
        metadata.name = name;
        functions.push_back(metadata);
    }

    SpanGeneratorConfig config;
    config.seed_hi = 3;
    config.seed_lo = 4;
    config.timestamps_are_unix = true;
    config.functions = &functions;
    config.sample_rate = 0.0;

    std::vector<SpanRecord> spans;
    SpanGenerator generator(config, [&](SpanRecord&& span) {
        spans.push_back(std::move(span));
    });
    CallStack stack(names, static_cast<Output*>(nullptr), -1, false, false,
                    &generator);
    stack.on_event(make_event(0, 30, kEventEnter, 100));
    stack.on_event(make_event(1, 30, kEventEnter, 200));
    stack.on_event(make_event(1, 30, kEventExit, 300));
    stack.on_event(make_event(0, 30, kEventExit, 400));

    CHECK(spans.empty());
    CHECK(generator.spans_sampled_out() == 2);

    // A kept root keeps all descendants.
    config.sample_rate = 1.0;
    std::vector<SpanRecord> kept;
    SpanGenerator kept_generator(config, [&](SpanRecord&& span) {
        kept.push_back(std::move(span));
    });
    CallStack kept_stack(names, static_cast<Output*>(nullptr), -1, false,
                         false, &kept_generator);
    kept_stack.on_event(make_event(0, 31, kEventEnter, 100));
    kept_stack.on_event(make_event(1, 31, kEventEnter, 200));
    kept_stack.on_event(make_event(1, 31, kEventExit, 300));
    kept_stack.on_event(make_event(0, 31, kEventExit, 400));
    CHECK(kept.size() == 2);
}

void test_flame_graph_sink()
{
    const std::vector<std::string> names = {"main", "A(int)"};
    std::vector<FunctionMetadata> functions;
    for (const auto& name : names) {
        FunctionMetadata metadata;
        metadata.name = name;
        functions.push_back(metadata);
    }

    FlameGraphSink sink(functions);
    CallStack stack(names, static_cast<Output*>(nullptr), -1, false, false,
                    &sink);
    stack.on_event(make_event(0, 40, kEventEnter, 100));
    stack.on_event(make_event(1, 40, kEventEnter, 200));
    stack.on_event(make_event(1, 40, kEventExit, 300));
    stack.on_event(make_event(0, 40, kEventExit, 400));

    const std::string folded = sink.render();
    CHECK(folded.find("main 1\n") != std::string::npos);
    CHECK(folded.find("main;A(int) 1\n") != std::string::npos);
    CHECK(sink.unique_stacks() == 2);

    FlameGraphSink incomplete(functions);
    CallStack incomplete_stack(names, static_cast<Output*>(nullptr), -1, false,
                               false, &incomplete);
    incomplete_stack.on_event(make_event(0, 41, kEventEnter, 100));
    incomplete_stack.on_event(make_event(1, 41, kEventEnter, 200));
    incomplete_stack.on_event(make_event(0, 41, kEventExit, 300));

    const std::string incomplete_folded = incomplete.render();
    CHECK(incomplete_folded.find("main;A(int);[incomplete] 1\n") !=
          std::string::npos);
    CHECK(incomplete_folded.find("main 1\n") != std::string::npos);
}

void test_text_parser()
{
    // Both the current `(a=1)` suffix and the older `[a=1]` suffix replay.
    for (const std::string suffix : {"(x=3)", "[x=3]"}) {
        const std::string path = temp_path();
        {
            std::ofstream out(path);
            out << "2026-11-12T10:00:00.000000000+00:00 10 : 0 -> main\n"
                   "2026-11-12T10:00:00.000001000+00:00 10 : 1 -> A(int) ";
            out << suffix << "\n";
            out << "2026-11-12T10:00:00.000002000+00:00 10 : 1 <- A(int)\n"
                   "2026-11-12T10:00:00.000003000+00:00 10 : 0 <- main\n"
                   "=== thread 10 ===\n";
        }

        std::vector<std::string> names;
        std::vector<FunctionMetadata> functions;
        std::vector<SpanRecord> spans;
        SpanGeneratorConfig config;
        config.seed_hi = 5;
        config.seed_lo = 6;
        config.timestamps_are_unix = true;
        config.functions = &functions;
        SpanGenerator builder(config, [&](SpanRecord&& span) {
            spans.push_back(std::move(span));
        });
        CallStack stack(names, static_cast<Output*>(nullptr), -1, false, false,
                        &builder);

        TraceParseOptions options;
        options.input_show_args = true;
        uint64_t last_ts = 0;
        const TraceParseStats stats = parse_text_trace(
            path, stack, names, functions, nullptr, options, &last_ts);
        stack.finish_spans(last_ts);
        unlink(path.c_str());

        CHECK(stats.event_lines == 4);
        CHECK(stats.ignored_lines == 1);
        CHECK(names.size() == 2);
        CHECK(spans.size() == 2);
        if (spans.size() == 2) {
            CHECK(spans[0].function.name == "A(int)");
            CHECK(spans[0].arguments == suffix);
            CHECK(spans[1].function.name == "main");
        }
    }
}

void test_text_parser_depth()
{
    const std::string path = temp_path();
    {
        std::ofstream out(path);
        out << "2026-11-12T20:53:55.235475704-08:00 26142 : 0 -> pq_getmsgstring\n"
               "2026-11-12T20:53:55.235479997-08:00 26142 : 0 -> pg_client_to_server\n"
               "2026-11-12T20:53:55.235482354-08:00 26142 : 0 -> pg_any_to_server\n"
               "2026-11-12T20:53:55.235484331-08:00 26142 : 1 -> pg_verify_mbstr\n"
               "2026-11-12T20:53:55.235489634-08:00 26142 : 1 <- pg_verify_mbstr\n"
               "2026-11-12T20:53:55.235489964-08:00 26142 : 0 <- pg_any_to_server\n"
               "2026-11-12T20:53:55.235490584-08:00 26142 : 0 -> pq_getmsgend\n"
               "2026-11-12T20:53:55.235492084-08:00 26142 : 0 <- pq_getmsgend\n"
               "2026-11-12T20:53:55.235494293-08:00 26142 : 0 -> exec_simple_query\n";
    }

    std::vector<std::string> names;
    std::vector<FunctionMetadata> functions;
    std::vector<SpanRecord> spans;
    SpanGeneratorConfig config;
    config.seed_hi = 5;
    config.seed_lo = 6;
    config.timestamps_are_unix = true;
    config.functions = &functions;
    SpanGenerator builder(config, [&](SpanRecord&& span) {
        spans.push_back(std::move(span));
    });
    CallStack stack(names, static_cast<Output*>(nullptr), -1, false, false,
                    &builder);

    TraceParseOptions options;
    uint64_t last_ts = 0;
    const TraceParseStats stats = parse_text_trace(
        path, stack, names, functions, nullptr, options, &last_ts);
    stack.finish_spans(last_ts);
    unlink(path.c_str());

    CHECK(stats.event_lines == 9);
    CHECK(stats.entries == 6);
    CHECK(stats.exits == 3);
    CHECK(spans.size() == 6);

    std::unordered_map<std::string, const SpanRecord*> by_name;
    for (const SpanRecord& span : spans)
        by_name[span.function.name] = &span;
    auto parent_of = [&](const std::string& name) -> uint64_t {
        const auto it = by_name.find(name);
        return it == by_name.end() ? UINT64_MAX
                                   : it->second->context.parent_span_id;
    };
    auto span_id_of = [&](const std::string& name) -> uint64_t {
        const auto it = by_name.find(name);
        return it == by_name.end() ? UINT64_MAX : it->second->context.span_id;
    };

    // The trace says these entries are all at depth 0, so consecutive ones are
    // siblings: the next depth-0 call must not become the previous one's child.
    CHECK(parent_of("pq_getmsgstring") == 0);
    CHECK(parent_of("pg_client_to_server") == 0);
    CHECK(parent_of("pg_any_to_server") == 0);
    CHECK(parent_of("pq_getmsgend") == 0);
    CHECK(parent_of("exec_simple_query") == 0);

    // A real depth+1 callee still nests under its caller.
    CHECK(parent_of("pg_verify_mbstr") == span_id_of("pg_any_to_server"));
}

void test_trace_metadata_roundtrip()
{
    const std::string path = temp_path();
    TraceMetadata source;
    source.service_name = "demo";
    source.service_namespace = "ns";
    source.pid = 123;
    source.monotonic_offset_ns = 99;
    source.seed_hi = 1;
    source.seed_lo = 2;
    source.return_mode = "ret";
    source.trace_scope = "thread";
    source.attach_mode = true;
    FunctionMetadata function;
    function.name = "A(int)";
    function.linkage_name = "_Z1Ai";
    function.module_path = "/tmp/app";
    function.module_build_id = "abc";
    function.file_offset = 0x42;
    function.source_file = "/src/a.cpp";
    function.source_line = 12;
    source.functions.push_back(function);

    CHECK(write_trace_metadata(path, source));
    TraceMetadata loaded;
    CHECK(read_trace_metadata(path, &loaded));
    unlink(path.c_str());

    CHECK(loaded.present);
    CHECK(loaded.service_name == "demo");
    CHECK(loaded.service_namespace == "ns");
    CHECK(loaded.pid == 123);
    CHECK(loaded.monotonic_offset_ns == 99);
    CHECK(loaded.return_mode == "ret");
    CHECK(loaded.trace_scope == "thread");
    CHECK(loaded.attach_mode);
    CHECK(loaded.functions.size() == 1);
    if (loaded.functions.size() == 1) {
        CHECK(loaded.functions[0].name == "A(int)");
        CHECK(loaded.functions[0].module_build_id == "abc");
        CHECK(loaded.functions[0].file_offset == 0x42);
        CHECK(loaded.functions[0].source_file == "/src/a.cpp");
        CHECK(loaded.functions[0].source_line == 12);
    }
}

void test_kernel_scheduler()
{
    const auto names = make_names();
    const std::string path = temp_path();
    std::string report;
    std::string trace;

    {
        Output output(path);
        CallStack stack(names, output, -1, false, true);
        KernelTimeline timeline(output, -1, false);
        timeline.set_target_tids({10});

        KernelEvent start = {};
        start.ts = 0;
        start.tid = 20;
        start.peer_tid = 10;
        start.kind = kKernelSchedSwitch;
        start.category = kKernelCatSched;
        start.a = 0;
        timeline.on_kernel_event(start, stack);

        TraceEvent enter = make_event(0, 10, kEventEnter, 0);
        timeline.on_function_event(enter, stack);
        stack.on_event(enter);

        KernelEvent out = {};
        out.ts = 1000;
        out.tid = 10;
        out.peer_tid = 20;
        out.kind = kKernelSchedSwitch;
        out.category = kKernelCatSched;
        out.a = 1;  // TASK_INTERRUPTIBLE
        timeline.on_kernel_event(out, stack);

        KernelEvent wake = {};
        wake.ts = 5000;
        wake.tid = 10;
        wake.peer_tid = 20;
        wake.kind = kKernelSchedWakeup;
        wake.category = kKernelCatSched;
        wake.a = 120;
        wake.c = 3;
        timeline.on_kernel_event(wake, stack);

        KernelEvent in = {};
        in.ts = 6000;
        in.tid = 20;
        in.peer_tid = 10;
        in.kind = kKernelSchedSwitch;
        in.category = kKernelCatSched;
        in.a = 0;
        timeline.on_kernel_event(in, stack);

        TraceEvent exit = make_event(0, 10, kEventExit, 7000);
        timeline.on_function_event(exit, stack);
        stack.on_event(exit);
        timeline.finish(7000, stack);

        report = timeline.format_report(names);
        output.stop();
    }
    trace = read_file(path);
    unlink(path.c_str());

    CHECK(trace.find("@SCHED switch_out") != std::string::npos);
    CHECK(trace.find("state=S") != std::string::npos);
    CHECK(trace.find("@SCHED wakeup") != std::string::npos);
    CHECK(trace.find("@SCHED switch_in") != std::string::npos);
    CHECK(trace.find("offcpu_ns=5000") != std::string::npos);
    CHECK(trace.find("runqueue_ns=1000") != std::string::npos);
    CHECK(report.find("0. main cpu=2.000us runnable=1.000us "
                      "blocked=4.000us") != std::string::npos);
    CHECK(report.find("partial=yes") != std::string::npos);
}

void test_kernel_futex_and_io()
{
    const auto names = make_names();
    const std::string path = temp_path();
    std::string trace;
    std::string report;

    {
        Output output(path);
        CallStack stack(names, output, -1, false, true);
        KernelTimeline timeline(output, -1, false);
        timeline.set_target_tids({10});

        TraceEvent enter = make_event(0, 10, kEventEnter, 0);
        timeline.on_function_event(enter, stack);
        stack.on_event(enter);

        KernelEvent futex_begin = {};
        futex_begin.ts = 100;
        futex_begin.tid = 10;
        futex_begin.kind = kKernelFutexEnter;
        futex_begin.category = kKernelCatFutex;
        futex_begin.a = 202;
        futex_begin.b = 0x1234;
        futex_begin.c = 0;  // FUTEX_WAIT
        futex_begin.d = 1;
        timeline.on_kernel_event(futex_begin, stack);

        KernelEvent switch_out = {};
        switch_out.ts = 200;
        switch_out.tid = 10;
        switch_out.peer_tid = 20;
        switch_out.kind = kKernelSchedSwitch;
        switch_out.category = kKernelCatSched;
        switch_out.a = 1;
        timeline.on_kernel_event(switch_out, stack);

        KernelEvent wake = {};
        wake.ts = 1200;
        wake.tid = 10;
        wake.peer_tid = 20;
        wake.kind = kKernelSchedWakeup;
        wake.category = kKernelCatSched;
        timeline.on_kernel_event(wake, stack);

        KernelEvent switch_in = {};
        switch_in.ts = 1500;
        switch_in.tid = 20;
        switch_in.peer_tid = 10;
        switch_in.kind = kKernelSchedSwitch;
        switch_in.category = kKernelCatSched;
        switch_in.a = 0;
        timeline.on_kernel_event(switch_in, stack);

        KernelEvent futex_end = {};
        futex_end.ts = 1600;
        futex_end.tid = 10;
        futex_end.kind = kKernelFutexExit;
        futex_end.category = kKernelCatFutex;
        futex_end.a = 202;
        futex_end.b = 0;
        timeline.on_kernel_event(futex_end, stack);

        KernelEvent read_begin = {};
        read_begin.ts = 1700;
        read_begin.tid = 10;
        read_begin.kind = CG_KEV_READ_ENTER;
        read_begin.category = kKernelCatIo;
        read_begin.a = 0;
        read_begin.b = 3;
        read_begin.d = 64;
        timeline.on_kernel_event(read_begin, stack);

        KernelEvent read_end = {};
        read_end.ts = 1900;
        read_end.tid = 10;
        read_end.kind = CG_KEV_READ_EXIT;
        read_end.category = kKernelCatIo;
        read_end.a = 0;
        read_end.b = 64;
        timeline.on_kernel_event(read_end, stack);

        TraceEvent exit = make_event(0, 10, kEventExit, 2000);
        timeline.on_function_event(exit, stack);
        stack.on_event(exit);
        timeline.finish(2000, stack);

        report = timeline.format_report(names);
        output.stop();
    }
    trace = read_file(path);
    unlink(path.c_str());

    CHECK(trace.find("@FUTEX wait_begin") != std::string::npos);
    CHECK(trace.find("@FUTEX wait_end") != std::string::npos);
    CHECK(trace.find("duration_ns=1500") != std::string::npos);
    CHECK(trace.find("@IO read_begin") != std::string::npos);
    CHECK(trace.find("fd=3 count=64") != std::string::npos);
    CHECK(trace.find("@IO read_end") != std::string::npos);
    CHECK(trace.find("duration_ns=200") != std::string::npos);
    CHECK(report.find("blocked(futex=1.000us") != std::string::npos);
}

void test_kernel_block_correlation()
{
    const std::string path = temp_path();
    std::string trace;
    {
        Output output(path);
        CallStack stack(make_names(), output, -1, false, false);
        KernelTimeline timeline(output, -1, false);
        timeline.set_target_tids({10});

        KernelEvent insert = {};
        insert.ts = 100;
        insert.kind = CG_KEV_BLOCK_INSERT;
        insert.category = kKernelCatBlock;
        insert.a = (8u << 20);  // 8:0
        insert.b = 1000;
        insert.c = 8;
        insert.d = 4096;
        timeline.on_kernel_event(insert, stack);

        KernelEvent issue = insert;
        issue.ts = 200;
        issue.kind = CG_KEV_BLOCK_ISSUE;
        timeline.on_kernel_event(issue, stack);

        KernelEvent complete = insert;
        complete.ts = 500;
        complete.kind = CG_KEV_BLOCK_COMPLETE;
        complete.d = 0;
        complete.e = 0;
        timeline.on_kernel_event(complete, stack);

        timeline.finish(500, stack);
        output.stop();
    }
    trace = read_file(path);
    unlink(path.c_str());

    CHECK(trace.find("@BLOCK rq_insert dev=8:0") != std::string::npos);
    CHECK(trace.find("@BLOCK rq_issue dev=8:0") != std::string::npos);
    CHECK(trace.find("queue_ns=100") != std::string::npos);
    CHECK(trace.find("@BLOCK rq_complete dev=8:0") != std::string::npos);
    CHECK(trace.find("device_ns=300") != std::string::npos);
    CHECK(trace.find("total_ns=400") != std::string::npos);
}

void test_kernel_output_global()
{
    const std::string path = temp_path();
    {
        Output output(path);
        output.emit_kernel(123, 0, kKernelDepthGlobal, "BLOCK", "rq_issue",
                           "dev=8:0 sector=1");
        output.emit_kernel(124, 42, kKernelDepthNone, "SCHED", "exit",
                           "prio=120");
        output.stop();
    }
    const std::string trace = read_file(path);
    unlink(path.c_str());

    CHECK(trace.find("0 : * @BLOCK rq_issue dev=8:0 sector=1") !=
          std::string::npos);
    CHECK(trace.find("42 : - @SCHED exit prio=120") != std::string::npos);
}

}  // namespace

int main()
{
    test_demangle();
    test_errno_string();
    test_latency_histogram();
    test_histogram_report();
    test_histogram_bar_proportional();
    test_histogram_tree_units();
    test_histogram_tree_unit_columns();
    test_histogram_incomplete();
    test_histogram_live_chain();
    test_histogram_siblings();
    test_histogram_roots();
    test_histogram_recursion();
    test_histogram_max_depth();
    test_kernel_scheduler();
    test_kernel_futex_and_io();
    test_kernel_block_correlation();
    test_kernel_output_global();
    test_basic_stack();
    test_desync();
    test_sp_unwind_on_enter();
    test_no_rsp_resync();
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
    test_span_generator();
    test_span_unwind_on_enter();
    test_span_trace_scope();
    test_root_sampling();
    test_otlp_encoding();
    test_flame_graph_sink();
    test_text_parser();
    test_text_parser_depth();
    test_trace_metadata_roundtrip();

    if (failures != 0) {
        fprintf(stderr, "%d test(s) failed\n", failures);
        return 1;
    }
    printf("all tests passed\n");
    return 0;
}
