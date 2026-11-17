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
#include "callgraph/trace_duration_histogram.h"
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

KernelEvent make_kernel_event(uint16_t kind, uint8_t category, uint32_t tid,
                              uint64_t ts)
{
    KernelEvent event = {};
    event.kind = kind;
    event.category = category;
    event.tid = tid;
    event.tgid = 1234;
    event.ts = ts;
    return event;
}

std::vector<std::string> make_names()
{
    return {"main", "A(int)", "B(int)"};
}

const SpanAttribute* find_span_attr(const SpanRecord& span, const char* key)
{
    for (const SpanAttribute& attribute : span.extra_attributes) {
        if (attribute.key == key)
            return &attribute;
    }
    return nullptr;
}

const SpanRecord* find_span(const std::vector<SpanRecord>& spans,
                            const std::string& name)
{
    for (const SpanRecord& span : spans) {
        if (span.function.name == name)
            return &span;
    }
    return nullptr;
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
        const size_t first = line.find_first_not_of(' ');
        const bool is_bar =
            first != std::string::npos &&
            line.find_first_not_of('-', first) == std::string::npos;
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

void test_histogram_call_path_totals()
{
    // A function reached from several call sites used to be split by caller
    // for its own total but merged for its children: palloc0's node showed one
    // caller's slice while AllocSetAlloc showed every palloc0 invocation, so
    // the child could be larger than its parent.  Path-keyed totals keep each
    // subtree's numbers consistent.
    const std::vector<std::string> names = {"main", "palloc0", "AllocSetAlloc",
                                            "helper"};
    const std::string path = temp_path();
    std::string report;

    {
        Output output(path);
        CallStack stack(names, output, -1, false, true);

        stack.on_event(make_event(0, 92, kEventEnter, 0));    // main

        stack.on_event(make_event(1, 92, kEventEnter, 100));  // palloc0
        stack.on_event(make_event(2, 92, kEventEnter, 110));  // AllocSetAlloc
        stack.on_event(make_event(2, 92, kEventExit, 210));   // 100 ns
        stack.on_event(make_event(1, 92, kEventExit, 400));   // 300 ns

        stack.on_event(make_event(3, 92, kEventEnter, 500));  // helper
        for (uint64_t base : {510ULL, 820ULL, 1130ULL}) {
            stack.on_event(make_event(1, 92, kEventEnter, base));
            stack.on_event(make_event(2, 92, kEventEnter, base + 10));
            stack.on_event(make_event(2, 92, kEventExit, base + 110));  // 100
            stack.on_event(make_event(1, 92, kEventExit, base + 290));  // 290
        }
        stack.on_event(make_event(3, 92, kEventExit, 1500));  // 1000 ns
        stack.on_event(make_event(0, 92, kEventExit, 2000));  // 2000 ns

        stack.finish_statistics();
        report = format_histogram_report(stack.stats(), names);
        output.stop();
    }
    unlink(path.c_str());

    const size_t tree_start = report.find("Tree:\n");
    const size_t hist_start = report.find("\nHistograms:", tree_start);
    CHECK(tree_start != std::string::npos);
    CHECK(hist_start != std::string::npos);
    const std::string tree =
        report.substr(tree_start, hist_start - tree_start);

    // palloc0 appears once per call path, each with its own subtree.
    CHECK(std::regex_search(tree, std::regex("palloc0[^\\n]*300ns")));
    CHECK(std::regex_search(tree, std::regex("palloc0[^\\n]*870ns")));
    CHECK(std::regex_search(tree,
                            std::regex("AllocSetAlloc[^\\n]*100ns")));
    CHECK(std::regex_search(tree,
                            std::regex("AllocSetAlloc[^\\n]*300ns")));
    // The old merged-edge total (4 x 100 ns under one palloc0 node) is gone.
    CHECK(tree.find("400ns") == std::string::npos);
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

void test_otel_drop_stats()
{
    CHECK(std::string(otel_drop_reason_name(OtelDropReason::QueueSpansFull)) ==
          "queue-spans-full");
    CHECK(std::string(otel_drop_reason_name(OtelDropReason::QueueBytesFull)) ==
          "queue-bytes-full");
    CHECK(std::string(otel_drop_reason_name(OtelDropReason::NoSink)) ==
          "no-sink");
    CHECK(std::string(otel_drop_reason_name(
              OtelDropReason::BatchEncodeFailed)) == "encode-failed");
    CHECK(std::string(otel_drop_reason_name(OtelDropReason::SendFailed)) ==
          "send-failed");
    CHECK(std::string(otel_drop_reason_name(OtelDropReason::WriteFailed)) ==
          "write-failed");

    OtelDropStats stats;
    stats.counts[static_cast<size_t>(OtelDropReason::QueueSpansFull)] = 2;
    stats.counts[static_cast<size_t>(OtelDropReason::SendFailed)] = 3;
    CHECK(stats.total() == 5);
}

void test_span_complete_traces()
{
    std::vector<SpanRecord> emitted;
    std::vector<std::vector<SpanRecord>> traces;

    SpanGeneratorConfig config;
    config.seed_hi = 11;
    config.seed_lo = 22;
    config.timestamps_are_unix = true;
    config.complete_traces = true;
    config.trace_buffer_spans = 10;
    config.trace_buffer_bytes = 1 << 20;

    SpanGenerator generator(
        config,
        [&](SpanRecord&& span) { emitted.push_back(std::move(span)); },
        [&](std::vector<SpanRecord>&& spans) {
            traces.push_back(std::move(spans));
        });

    const uint64_t root =
        generator.on_function_enter(10, 0, 0, 100, "", 0);
    const uint64_t child =
        generator.on_function_enter(10, 1, 1, 101, "", root);
    generator.on_function_exit(10, child, 1, 102, SpanCloseReason::Return);

    CHECK(emitted.empty());
    CHECK(traces.empty());

    generator.on_function_exit(10, root, 0, 103, SpanCloseReason::Return);
    CHECK(traces.size() == 1);
    if (traces.size() == 1) {
        CHECK(traces[0].size() == 2);
        CHECK(traces[0][0].context.parent_span_id == 0);
        CHECK(traces[0][1].context.parent_span_id == root);
    }
    CHECK(generator.traces_flushed() == 1);
    CHECK(generator.spans_trace_buffer_dropped() == 0);

    SpanGeneratorConfig overflow_config = config;
    overflow_config.trace_buffer_spans = 1;
    std::vector<std::vector<SpanRecord>> overflow_traces;
    SpanGenerator overflow(
        overflow_config,
        [&](SpanRecord&& span) { emitted.push_back(std::move(span)); },
        [&](std::vector<SpanRecord>&& spans) {
            overflow_traces.push_back(std::move(spans));
        });

    const uint64_t overflow_root =
        overflow.on_function_enter(20, 0, 0, 200, "", 0);
    const uint64_t overflow_child =
        overflow.on_function_enter(20, 1, 1, 201, "", overflow_root);
    overflow.on_function_exit(20, overflow_child, 1, 202,
                              SpanCloseReason::Return);
    overflow.on_function_exit(20, overflow_root, 0, 203,
                              SpanCloseReason::Return);

    CHECK(overflow_traces.empty());
    CHECK(overflow.traces_overflowed() == 1);
    CHECK(overflow.spans_trace_buffer_dropped() == 2);
}

void test_otel_trace_drop()
{
    OtelConfig config;
    OtelExporter exporter(config);
    std::vector<SpanRecord> spans(2);
    exporter.export_trace(std::move(spans));
    const OtelDropStats stats = exporter.drop_stats();
    CHECK(stats.counts[static_cast<size_t>(OtelDropReason::NoSink)] == 2);
    CHECK(exporter.dropped() == 2);
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
    span.quantile = 0.9875;
    span.arguments = "(x=3)";

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
    CHECK(json.find("\"key\":\"callgraph.quantile\"") != std::string::npos);
    CHECK(json.find("\"doubleValue\":0.9875") != std::string::npos);
    CHECK(json.find("\"key\":\"code.arguments\"") != std::string::npos);
    CHECK(json.find("\"stringValue\":\"(x=3)\"") != std::string::npos);

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
        bool have_quantile = false;
        bool have_arguments = false;
        for (const auto& attribute : encoded_span.attributes()) {
            if (attribute.key() == "callgraph.quantile") {
                have_quantile = true;
                CHECK(attribute.value().double_value() == 0.9875);
            }
            if (attribute.key() == "code.arguments") {
                have_arguments = true;
                CHECK(attribute.value().string_value() == "(x=3)");
            }
        }
        CHECK(have_quantile);
        CHECK(have_arguments);
#endif
    }
}

void test_otlp_kernel_span_encoding()
{
    SpanRecord span;
    span.kernel = true;
    span.context.trace_id[15] = 2;
    span.context.span_id = 0x99;
    span.context.parent_span_id = 0x11;
    span.tid = 7;
    span.depth = 3;
    span.start_unix_ns = 100;
    span.end_unix_ns = 200;
    span.function.name = "read";
    span.thread_name = "worker";
    span.extra_attributes.push_back(
        make_span_string("callgraph.kernel.event", "read"));
    span.extra_attributes.push_back(
        make_span_int("callgraph.kernel.ret", -1));
    span.extra_attributes.push_back(
        make_span_bool("callgraph.kernel.point", false));

    OtelConfig config;
    const std::string json = encode_otlp_request({span}, config);
    CHECK(json.find("\"name\":\"read\"") != std::string::npos);
    CHECK(json.find("\"key\":\"callgraph.kernel.event\"") != std::string::npos);
    CHECK(json.find("\"key\":\"callgraph.kernel.ret\"") != std::string::npos);
    CHECK(json.find("\"intValue\":\"-1\"") != std::string::npos);
    CHECK(json.find("\"key\":\"code.function.name\"") == std::string::npos);

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
        CHECK(encoded_span.name() == "read");
        bool have_ret = false;
        bool have_function = false;
        for (const auto& attribute : encoded_span.attributes()) {
            if (attribute.key() == "callgraph.kernel.ret") {
                have_ret = true;
                CHECK(attribute.value().int_value() == -1);
            }
            if (attribute.key() == "code.function.name")
                have_function = true;
        }
        CHECK(have_ret);
        CHECK(!have_function);
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

void test_trace_duration_histogram()
{
    TraceDurationHistogram empty;
    CHECK(empty.count() == 0);
    CHECK(empty.quantile(0.99) == 0);
    CHECK(empty.cdf(1000) == 0.0);

    TraceDurationHistogram hist;
    for (uint64_t i = 1; i <= 1000; ++i)
        hist.add(i * 1000);
    CHECK(hist.count() == 1000);

    const uint64_t p50 = hist.quantile(0.5);
    const uint64_t p99 = hist.quantile(0.99);
    CHECK(p50 >= 480000 && p50 <= 520000);
    CHECK(p99 >= 980000 && p99 <= 1000000);
    CHECK(hist.cdf(1000) > 0.0);
    CHECK(hist.cdf(1000) < 0.01);
    CHECK(hist.cdf(1000000) > 0.99);
    CHECK(hist.cdf(1000000) <= 1.0);

    TraceDurationHistogram zeros;
    zeros.add(0);
    CHECK(zeros.count() == 1);
    CHECK(zeros.quantile(0.5) == 0);
}

void test_ingest_sampling_and_log_rate_limit()
{
    const auto names = make_names();

    std::vector<SpanRecord> spans;
    SpanGeneratorConfig config;
    config.seed_hi = 5;
    config.seed_lo = 6;
    config.timestamps_are_unix = true;
    SpanGenerator generator(config, [&](SpanRecord&& span) {
        spans.push_back(std::move(span));
    });

    const std::string path = temp_path();
    {
        Output output(path);
        CallStack stack(names, output, -1, false, false, &generator);
        stack.set_ingest_sample_rate(0.0);
        stack.on_event(make_event(0, 60, kEventEnter, 100));
        stack.on_event(make_event(1, 60, kEventEnter, 200));
        stack.on_event(make_event(1, 60, kEventExit, 300));
        stack.on_event(make_event(0, 60, kEventExit, 400));
        CHECK(stack.entries() == 2);
        CHECK(stack.returns() == 2);
        CHECK(stack.desyncs() == 0);
        CHECK(stack.ingest_skipped_roots() == 1);
        output.stop();
    }
    CHECK(spans.empty());
    CHECK(read_lines(path).empty());
    unlink(path.c_str());

    const std::string limited_path = temp_path();
    {
        Output output(limited_path);
        CallStack stack(names, output, -1, false);
        stack.set_log_rate_limit(2);
        stack.on_event(make_event(0, 61, kEventEnter, 0));
        stack.on_event(make_event(1, 61, kEventEnter, 0));
        stack.on_event(make_event(1, 61, kEventExit, 0));
        stack.on_event(make_event(0, 61, kEventExit, 0));
        CHECK(stack.lines_suppressed() == 2);
        stack.on_event(make_event(0, 61, kEventEnter, 1000000000ULL));
        stack.on_event(make_event(0, 61, kEventExit, 1000000000ULL));
        output.stop();
    }
    const auto lines = read_lines(limited_path);
    CHECK(lines.size() == 4);
    unlink(limited_path.c_str());
}

void test_outlier_sampling()
{
    const std::vector<std::string> names = {"main", "A(int)"};
    std::vector<FunctionMetadata> functions;
    for (const auto& name : names) {
        FunctionMetadata metadata;
        metadata.name = name;
        functions.push_back(metadata);
    }

    SpanGeneratorConfig config;
    config.seed_hi = 7;
    config.seed_lo = 8;
    config.timestamps_are_unix = true;
    config.functions = &functions;
    config.sample_rate = 0.0;
    config.complete_traces = true;
    config.outlier_quantile = 0.9;
    config.outlier_warmup_traces = 3;
    config.trace_buffer_spans = 100;
    config.trace_buffer_bytes = 1 << 20;

    std::vector<SpanRecord> exported;
    SpanGenerator generator(config, [&](SpanRecord&& span) {
        exported.push_back(std::move(span));
    });
    CallStack stack(names, static_cast<Output*>(nullptr), -1, false, false,
                    &generator);

    uint64_t ts = 0;
    auto trace = [&](uint32_t tid, uint64_t duration) {
        stack.on_event(make_event(0, tid, kEventEnter, ts));
        stack.on_event(make_event(1, tid, kEventEnter, ts + 10));
        stack.on_event(make_event(1, tid, kEventExit, ts + 20));
        stack.on_event(make_event(0, tid, kEventExit, ts + duration));
        ts += duration + 1000;
    };

    // The warm-up and the uniform workload follow the baseline sample, which
    // is zero here, so only the final long trace is exported.
    for (int i = 0; i < 23; ++i)
        trace(50 + static_cast<uint32_t>(i), 1000);
    trace(99, 100000);

    CHECK(generator.outlier_traces_seen() == 24);
    CHECK(generator.traces_outlier_filtered() == 23);
    CHECK(generator.spans_outlier_filtered() == 46);
    CHECK(generator.traces_flushed() == 1);
    CHECK(generator.outlier_threshold_ns() > 0);
    CHECK(exported.size() == 2);

    const SpanRecord* root = nullptr;
    for (const auto& span : exported) {
        if (span.context.parent_span_id == 0)
            root = &span;
        else
            CHECK(span.quantile < 0.0);
    }
    CHECK(root != nullptr);
    if (root) {
        CHECK(root->quantile > 0.9);
        CHECK(root->quantile <= 1.0);
        CHECK(root->end_unix_ns - root->start_unix_ns == 100000);
    }
}

void test_outlier_overflow_keeps_duration()
{
    const std::vector<std::string> names = {"main", "A(int)"};
    std::vector<FunctionMetadata> functions;
    for (const auto& name : names) {
        FunctionMetadata metadata;
        metadata.name = name;
        functions.push_back(metadata);
    }

    SpanGeneratorConfig config;
    config.seed_hi = 9;
    config.seed_lo = 10;
    config.timestamps_are_unix = true;
    config.functions = &functions;
    config.complete_traces = true;
    config.outlier_quantile = 0.9;
    config.outlier_warmup_traces = 0;
    config.trace_buffer_spans = 1;
    config.trace_buffer_bytes = 1 << 20;

    std::vector<SpanRecord> exported;
    SpanGenerator generator(config, [&](SpanRecord&& span) {
        exported.push_back(std::move(span));
    });
    CallStack stack(names, static_cast<Output*>(nullptr), -1, false, false,
                    &generator);

    uint64_t ts = 0;
    auto trace = [&](uint32_t tid, uint64_t duration) {
        stack.on_event(make_event(0, tid, kEventEnter, ts));
        stack.on_event(make_event(1, tid, kEventEnter, ts + 10));
        stack.on_event(make_event(1, tid, kEventExit, ts + 20));
        stack.on_event(make_event(0, tid, kEventExit, ts + duration));
        ts += duration + 1000;
    };
    trace(70, 1000);
    trace(71, 2000);

    CHECK(generator.traces_overflowed() == 2);
    CHECK(generator.outlier_traces_seen() == 2);
    CHECK(exported.empty());
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
        options.show_args = true;
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

void test_kernel_memory()
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

        KernelEvent fault = {};
        fault.ts = 100;
        fault.tid = 10;
        fault.kind = kKernelPageFaultUser;
        fault.category = kKernelCatMm;
        fault.a = 0x1000;
        fault.b = 0x2000;
        fault.c = 0x4;
        timeline.on_kernel_event(fault, stack);

        KernelEvent reclaim_begin = {};
        reclaim_begin.ts = 200;
        reclaim_begin.tid = 10;
        reclaim_begin.kind = kKernelDirectReclaimBegin;
        reclaim_begin.category = kKernelCatMm;
        reclaim_begin.a = 0;
        reclaim_begin.b = 0x200;
        timeline.on_kernel_event(reclaim_begin, stack);

        KernelEvent switch_out = {};
        switch_out.ts = 300;
        switch_out.tid = 10;
        switch_out.peer_tid = 20;
        switch_out.kind = kKernelSchedSwitch;
        switch_out.category = kKernelCatSched;
        switch_out.a = 1;  // TASK_INTERRUPTIBLE
        timeline.on_kernel_event(switch_out, stack);

        KernelEvent wake = {};
        wake.ts = 1000;
        wake.tid = 10;
        wake.peer_tid = 20;
        wake.kind = kKernelSchedWakeup;
        wake.category = kKernelCatSched;
        timeline.on_kernel_event(wake, stack);

        KernelEvent switch_in = {};
        switch_in.ts = 1200;
        switch_in.tid = 20;
        switch_in.peer_tid = 10;
        switch_in.kind = kKernelSchedSwitch;
        switch_in.category = kKernelCatSched;
        switch_in.a = 0;
        timeline.on_kernel_event(switch_in, stack);

        KernelEvent reclaim_end = {};
        reclaim_end.ts = 1300;
        reclaim_end.tid = 10;
        reclaim_end.kind = kKernelDirectReclaimEnd;
        reclaim_end.category = kKernelCatMm;
        reclaim_end.a = 42;
        timeline.on_kernel_event(reclaim_end, stack);

        TraceEvent exit = make_event(0, 10, kEventExit, 1400);
        timeline.on_function_event(exit, stack);
        stack.on_event(exit);
        timeline.finish(1400, stack);

        report = timeline.format_report(names);
        output.stop();
    }
    trace = read_file(path);
    unlink(path.c_str());

    CHECK(trace.find("@MM page_fault space=user address=0x1000") !=
          std::string::npos);
    CHECK(trace.find("ip=0x2000 error=0x4") != std::string::npos);
    CHECK(trace.find("@MM direct_reclaim_begin id=1 order=0 gfp=0x200") !=
          std::string::npos);
    CHECK(trace.find("@MM direct_reclaim_end") != std::string::npos);
    CHECK(trace.find("nr_reclaimed=42 duration_ns=1100") !=
          std::string::npos);
    CHECK(report.find("blocked(memory=700ns") != std::string::npos);
    CHECK(report.find("faults=1") != std::string::npos);
}

void test_kernel_network()
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

        KernelEvent socket_begin = {};
        socket_begin.ts = 100;
        socket_begin.tid = 10;
        socket_begin.kind = CG_KEV_NET_SOCKET_ENTER;
        socket_begin.category = kKernelCatNet;
        socket_begin.a = 0;
        socket_begin.b = 2;  // AF_INET
        socket_begin.c = 1;  // SOCK_STREAM
        socket_begin.d = 0;
        timeline.on_kernel_event(socket_begin, stack);

        KernelEvent socket_end = {};
        socket_end.ts = 200;
        socket_end.tid = 10;
        socket_end.kind = CG_KEV_NET_SOCKET_EXIT;
        socket_end.category = kKernelCatNet;
        socket_end.a = 0;
        socket_end.b = 5;
        timeline.on_kernel_event(socket_end, stack);

        KernelEvent send_begin = {};
        send_begin.ts = 300;
        send_begin.tid = 10;
        send_begin.kind = CG_KEV_NET_SENDTO_ENTER;
        send_begin.category = kKernelCatNet;
        send_begin.a = 0;
        send_begin.b = 5;
        send_begin.c = 0x4000;
        send_begin.d = 4;
        send_begin.e = 0;
        send_begin.f = 0x5000;
        send_begin.g = 16;
        timeline.on_kernel_event(send_begin, stack);

        KernelEvent send_end = {};
        send_end.ts = 400;
        send_end.tid = 10;
        send_end.kind = CG_KEV_NET_SENDTO_EXIT;
        send_end.category = kKernelCatNet;
        send_end.a = 0;
        send_end.b = 4;
        timeline.on_kernel_event(send_end, stack);

        KernelEvent recv_begin = {};
        recv_begin.ts = 500;
        recv_begin.tid = 10;
        recv_begin.kind = CG_KEV_NET_RECVFROM_ENTER;
        recv_begin.category = kKernelCatNet;
        recv_begin.a = 0;
        recv_begin.b = 5;
        recv_begin.c = 0x6000;
        recv_begin.d = 64;
        recv_begin.e = 0;
        recv_begin.f = 0x7000;
        recv_begin.g = 0x8000;
        timeline.on_kernel_event(recv_begin, stack);

        KernelEvent switch_out = {};
        switch_out.ts = 600;
        switch_out.tid = 10;
        switch_out.peer_tid = 20;
        switch_out.kind = kKernelSchedSwitch;
        switch_out.category = kKernelCatSched;
        switch_out.a = 1;
        timeline.on_kernel_event(switch_out, stack);

        KernelEvent wake = {};
        wake.ts = 1000;
        wake.tid = 10;
        wake.peer_tid = 20;
        wake.kind = kKernelSchedWakeup;
        wake.category = kKernelCatSched;
        timeline.on_kernel_event(wake, stack);

        KernelEvent switch_in = {};
        switch_in.ts = 1100;
        switch_in.tid = 20;
        switch_in.peer_tid = 10;
        switch_in.kind = kKernelSchedSwitch;
        switch_in.category = kKernelCatSched;
        switch_in.a = 0;
        timeline.on_kernel_event(switch_in, stack);

        KernelEvent recv_end = {};
        recv_end.ts = 1200;
        recv_end.tid = 10;
        recv_end.kind = CG_KEV_NET_RECVFROM_EXIT;
        recv_end.category = kKernelCatNet;
        recv_end.a = 0;
        recv_end.b = 64;
        timeline.on_kernel_event(recv_end, stack);

        TraceEvent exit = make_event(0, 10, kEventExit, 1300);
        timeline.on_function_event(exit, stack);
        stack.on_event(exit);
        timeline.finish(1300, stack);

        report = timeline.format_report(names);
        output.stop();
    }
    trace = read_file(path);
    unlink(path.c_str());

    CHECK(trace.find("@NET socket_begin id=1 family=2 type=1 protocol=0") !=
          std::string::npos);
    CHECK(trace.find("@NET socket_end id=1 ret=5 duration_ns=100") !=
          std::string::npos);
    CHECK(trace.find("@NET sendto_begin id=2 fd=5 len=4") !=
          std::string::npos);
    CHECK(trace.find("@NET sendto_end id=2 ret=4 duration_ns=100") !=
          std::string::npos);
    CHECK(trace.find("@NET recvfrom_begin id=3 fd=5 size=64") !=
          std::string::npos);
    CHECK(trace.find("@NET recvfrom_end id=3 ret=64 duration_ns=700") !=
          std::string::npos);
    CHECK(report.find("blocked(net=400ns") != std::string::npos);
}

void test_kernel_histogram_report()
{
    const auto names = make_names();
    const std::string path = temp_path();
    std::string report;

    {
        Output output(path);
        CallStack stack(names, output, -1, false, true);
        KernelTimeline timeline(output, -1, false);
        timeline.set_target_tids({10});
        timeline.set_collect_histograms(true);

        TraceEvent main_enter = make_event(0, 10, kEventEnter, 0);
        timeline.on_function_event(main_enter, stack);
        stack.on_event(main_enter);

        TraceEvent a_enter = make_event(1, 10, kEventEnter, 100);
        timeline.on_function_event(a_enter, stack);
        stack.on_event(a_enter);

        KernelEvent futex_begin = make_kernel_event(
            CG_KEV_FUTEX_ENTER, CG_KCAT_FUTEX, 10, 200);
        futex_begin.a = 202;
        futex_begin.b = 0x1234;
        futex_begin.c = 0;  // FUTEX_WAIT
        timeline.on_kernel_event(futex_begin, stack);

        KernelEvent futex_end = make_kernel_event(
            CG_KEV_FUTEX_EXIT, CG_KCAT_FUTEX, 10, 1200);
        futex_end.a = 202;
        futex_end.b = 0;
        timeline.on_kernel_event(futex_end, stack);

        KernelEvent read_begin =
            make_kernel_event(CG_KEV_READ_ENTER, CG_KCAT_IO, 10, 1300);
        read_begin.a = 0;
        read_begin.b = 3;
        read_begin.d = 64;
        timeline.on_kernel_event(read_begin, stack);

        KernelEvent read_end =
            make_kernel_event(CG_KEV_READ_EXIT, CG_KCAT_IO, 10, 1500);
        read_end.a = 0;
        read_end.b = 64;
        timeline.on_kernel_event(read_end, stack);

        KernelEvent fault = make_kernel_event(
            CG_KEV_PAGE_FAULT_USER, CG_KCAT_MM, 10, 1600);
        fault.a = 0x1000;
        fault.b = 0x2000;
        fault.c = 4;
        timeline.on_kernel_event(fault, stack);

        TraceEvent a_exit = make_event(1, 10, kEventExit, 1800);
        timeline.on_function_event(a_exit, stack);
        stack.on_event(a_exit);

        TraceEvent main_exit = make_event(0, 10, kEventExit, 2000);
        timeline.on_function_event(main_exit, stack);
        stack.on_event(main_exit);

        timeline.finish(2000, stack);
        stack.finish_statistics();

        report = format_histogram_report(stack.stats(), names,
                                         &timeline.kernel_histograms());
        output.stop();
    }
    unlink(path.c_str());

    const std::string clean = without_histogram_bars(report);
    CHECK(clean.find("1. A(int)\n   calls=1  total=1.70us") !=
          std::string::npos);
    CHECK(clean.find("   kernel:\n") != std::string::npos);
    CHECK(clean.find("     @futex\n       calls=1  total=1.00us") !=
          std::string::npos);
    CHECK(clean.find("     @read\n       calls=1  total=200ns") !=
          std::string::npos);
    CHECK(clean.find("     page_fault.user\n       calls=1  total=0ns") !=
          std::string::npos);
}

void test_kernel_histogram_roots()
{
    const auto names = make_names();
    const std::string path = temp_path();
    std::string report;

    {
        Output output(path);
        CallStack stack(names, output, -1, false, true);
        KernelTimeline timeline(output, -1, false);
        timeline.set_target_tids({20});
        timeline.set_collect_histograms(true);

        // Root A(int) -> main with a 100ns read.
        TraceEvent a_enter = make_event(1, 20, kEventEnter, 0);
        timeline.on_function_event(a_enter, stack);
        stack.on_event(a_enter);
        TraceEvent main_a = make_event(0, 20, kEventEnter, 10);
        timeline.on_function_event(main_a, stack);
        stack.on_event(main_a);
        KernelEvent read_a =
            make_kernel_event(CG_KEV_READ_ENTER, CG_KCAT_IO, 20, 20);
        read_a.a = 0;
        read_a.b = 3;
        timeline.on_kernel_event(read_a, stack);
        KernelEvent read_a_end =
            make_kernel_event(CG_KEV_READ_EXIT, CG_KCAT_IO, 20, 120);
        read_a_end.a = 0;
        read_a_end.b = 1;
        timeline.on_kernel_event(read_a_end, stack);
        TraceEvent main_a_exit = make_event(0, 20, kEventExit, 130);
        timeline.on_function_event(main_a_exit, stack);
        stack.on_event(main_a_exit);
        TraceEvent a_exit = make_event(1, 20, kEventExit, 200);
        timeline.on_function_event(a_exit, stack);
        stack.on_event(a_exit);

        // Root B(int) -> main with a 300ns read.
        TraceEvent b_enter = make_event(2, 20, kEventEnter, 300);
        timeline.on_function_event(b_enter, stack);
        stack.on_event(b_enter);
        TraceEvent main_b = make_event(0, 20, kEventEnter, 310);
        timeline.on_function_event(main_b, stack);
        stack.on_event(main_b);
        KernelEvent read_b =
            make_kernel_event(CG_KEV_READ_ENTER, CG_KCAT_IO, 20, 320);
        read_b.a = 0;
        read_b.b = 3;
        timeline.on_kernel_event(read_b, stack);
        KernelEvent read_b_end =
            make_kernel_event(CG_KEV_READ_EXIT, CG_KCAT_IO, 20, 620);
        read_b_end.a = 0;
        read_b_end.b = 1;
        timeline.on_kernel_event(read_b_end, stack);
        TraceEvent main_b_exit = make_event(0, 20, kEventExit, 630);
        timeline.on_function_event(main_b_exit, stack);
        stack.on_event(main_b_exit);
        TraceEvent b_exit = make_event(2, 20, kEventExit, 700);
        timeline.on_function_event(b_exit, stack);
        stack.on_event(b_exit);

        timeline.finish(700, stack);
        stack.finish_statistics();

        report = format_histogram_report(stack.stats(), names,
                                         &timeline.kernel_histograms());
        output.stop();
    }
    unlink(path.c_str());

    const size_t root_a = report.find("0. A(int)");
    const size_t root_b = report.find("0. B(int)");
    const size_t read_a = report.find("total=100ns");
    const size_t read_b = report.find("total=300ns");
    CHECK(root_a != std::string::npos);
    CHECK(root_b != std::string::npos);
    CHECK(read_a != std::string::npos);
    CHECK(read_b != std::string::npos);
    if (root_a != std::string::npos && root_b != std::string::npos &&
        read_a != std::string::npos && read_b != std::string::npos) {
        CHECK(root_a < read_a);
        CHECK(read_a < root_b);
        CHECK(root_b < read_b);
    }

    size_t reads = 0;
    for (size_t pos = report.find("@read"); pos != std::string::npos;
         pos = report.find("@read", pos + 1))
        ++reads;
    CHECK(reads == 2);
}

void test_kernel_histogram_incomplete()
{
    const auto names = make_names();
    const std::string path = temp_path();
    std::string report;

    {
        Output output(path);
        CallStack stack(names, output, -1, false, true);
        KernelTimeline timeline(output, -1, false);
        timeline.set_target_tids({30});
        timeline.set_collect_histograms(true);

        TraceEvent main_enter = make_event(0, 30, kEventEnter, 0);
        timeline.on_function_event(main_enter, stack);
        stack.on_event(main_enter);

        // Exit without a matching enter.
        KernelEvent read_end =
            make_kernel_event(CG_KEV_READ_EXIT, CG_KCAT_IO, 30, 100);
        read_end.a = 0;
        read_end.b = 1;
        timeline.on_kernel_event(read_end, stack);

        // Enter and leave open until shutdown.
        KernelEvent futex_begin = make_kernel_event(
            CG_KEV_FUTEX_ENTER, CG_KCAT_FUTEX, 30, 200);
        futex_begin.a = 202;
        futex_begin.b = 0x1234;
        futex_begin.c = 0;
        timeline.on_kernel_event(futex_begin, stack);

        // Reclaim left open until shutdown.
        KernelEvent reclaim_begin = make_kernel_event(
            CG_KEV_DIRECT_RECLAIM_BEGIN, CG_KCAT_MM, 30, 300);
        reclaim_begin.a = 0;
        reclaim_begin.b = 0x1;
        timeline.on_kernel_event(reclaim_begin, stack);

        timeline.finish(600, stack);
        stack.finish_statistics();

        report = format_histogram_report(stack.stats(), names,
                                         &timeline.kernel_histograms());
        output.stop();
    }
    unlink(path.c_str());

    CHECK(report.find("@read  [incomplete]") != std::string::npos);
    CHECK(report.find("@futex  [incomplete]") != std::string::npos);
    CHECK(report.find("direct_reclaim  [incomplete]") != std::string::npos);
    CHECK(report.find("calls=1  total=0ns") != std::string::npos);
    CHECK(report.find("calls=1  total=400ns") != std::string::npos);
    CHECK(report.find("calls=1  total=300ns") != std::string::npos);
}

void test_kernel_text_ids_without_span_sink()
{
    const auto names = make_names();
    const std::string path = temp_path();
    std::string trace;

    {
        Output output(path);
        CallStack stack(names, output, -1, false);
        KernelTimeline timeline(output, -1, false);
        timeline.set_target_tids({15});

        TraceEvent main_enter = make_event(0, 15, kEventEnter, 100);
        timeline.on_function_event(main_enter, stack);
        stack.on_event(main_enter);

        KernelEvent reclaim_begin = make_kernel_event(
            CG_KEV_DIRECT_RECLAIM_BEGIN, CG_KCAT_MM, 15, 200);
        reclaim_begin.a = 0;
        reclaim_begin.b = 0x1;
        timeline.on_kernel_event(reclaim_begin, stack);
        KernelEvent reclaim_end = make_kernel_event(
            CG_KEV_DIRECT_RECLAIM_END, CG_KCAT_MM, 15, 300);
        reclaim_end.a = 1;
        timeline.on_kernel_event(reclaim_end, stack);

        KernelEvent futex_begin =
            make_kernel_event(CG_KEV_FUTEX_ENTER, CG_KCAT_FUTEX, 15, 400);
        futex_begin.a = 202;
        futex_begin.b = 0x1234;
        futex_begin.c = 0;
        futex_begin.d = 9;
        timeline.on_kernel_event(futex_begin, stack);
        KernelEvent futex_end =
            make_kernel_event(CG_KEV_FUTEX_EXIT, CG_KCAT_FUTEX, 15, 500);
        futex_end.a = 202;
        futex_end.b = 0;
        timeline.on_kernel_event(futex_end, stack);

        TraceEvent main_exit = make_event(0, 15, kEventExit, 600);
        timeline.on_function_event(main_exit, stack);
        stack.on_event(main_exit);
        timeline.finish(700, stack);
        output.stop();
    }

    trace = read_file(path);
    unlink(path.c_str());

    CHECK(trace.find("@MM direct_reclaim_begin id=1") != std::string::npos);
    CHECK(trace.find("@FUTEX wait_begin id=2") != std::string::npos);
}

void test_kernel_span_export()
{
    const std::vector<std::string> names = {"main", "A(int)"};
    std::vector<FunctionMetadata> functions;
    for (const auto& name : names) {
        FunctionMetadata metadata;
        metadata.name = name;
        functions.push_back(metadata);
    }
    const std::string path = temp_path();

    auto config = [&] {
        SpanGeneratorConfig value;
        value.seed_hi = 21;
        value.seed_lo = 22;
        value.timestamps_are_unix = true;
        value.functions = &functions;
        return value;
    };

    // Syscall interval with enter parameters and return value.
    {
        SpanGeneratorConfig builder = config();
        std::vector<SpanRecord> spans;
        SpanGenerator generator(builder, [&](SpanRecord&& span) {
            spans.push_back(std::move(span));
        });
        CallStack stack(names, static_cast<Output*>(nullptr), -1, false, false,
                        &generator);
        Output output(path);
        KernelTimeline timeline(output, -1, false);
        timeline.set_target_tids({7});
        timeline.set_kernel_span_sink(&generator);

        auto enter = [&](uint64_t ts) {
            TraceEvent event = make_event(0, 7, kEventEnter, ts);
            timeline.on_function_event(event, stack);
            stack.on_event(event);
        };
        auto exit = [&](uint64_t ts) {
            TraceEvent event = make_event(0, 7, kEventExit, ts);
            timeline.on_function_event(event, stack);
            stack.on_event(event);
        };

        enter(100);
        KernelEvent begin =
            make_kernel_event(CG_KEV_FUTEX_ENTER, CG_KCAT_FUTEX, 7, 200);
        begin.a = 202;
        begin.b = 0x1234;
        begin.c = 0;
        begin.d = 9;
        timeline.on_kernel_event(begin, stack);
        KernelEvent end =
            make_kernel_event(CG_KEV_FUTEX_EXIT, CG_KCAT_FUTEX, 7, 300);
        end.a = 202;
        end.b = 0;
        timeline.on_kernel_event(end, stack);
        exit(400);
        timeline.finish(500, stack);
        output.stop();

        const SpanRecord* main = find_span(spans, "main");
        const SpanRecord* futex = find_span(spans, "@futex");
        CHECK(main != nullptr);
        CHECK(futex != nullptr);
        if (main && futex) {
            CHECK(main->kernel == false);
            CHECK(futex->kernel);
            CHECK(futex->context.parent_span_id == main->context.span_id);
            CHECK(futex->context.trace_id == main->context.trace_id);
            CHECK(futex->tid == 7);
            CHECK(futex->depth == 1);
            CHECK(futex->start_unix_ns == 200);
            CHECK(futex->end_unix_ns == 300);
            const SpanAttribute* category =
                find_span_attr(*futex, "callgraph.kernel.category");
            const SpanAttribute* event =
                find_span_attr(*futex, "callgraph.kernel.event");
            const SpanAttribute* ret =
                find_span_attr(*futex, "callgraph.kernel.ret");
            const SpanAttribute* duration =
                find_span_attr(*futex, "callgraph.kernel.duration_ns");
            const SpanAttribute* user_depth =
                find_span_attr(*futex, "callgraph.kernel.user_depth");
            CHECK(category != nullptr && category->string_value == "FUTEX");
            CHECK(event != nullptr && event->string_value == "futex");
            CHECK(ret != nullptr && ret->int_value == 0);
            CHECK(duration != nullptr && duration->int_value == 100);
            CHECK(user_depth != nullptr && user_depth->int_value == 0);
        }
    }

    // Off-CPU and runqueue intervals, with the wakeup point nested under
    // off-CPU before runqueue opens.
    {
        SpanGeneratorConfig builder = config();
        builder.seed_hi += 2;
        std::vector<SpanRecord> spans;
        SpanGenerator generator(builder, [&](SpanRecord&& span) {
            spans.push_back(std::move(span));
        });
        CallStack stack(names, static_cast<Output*>(nullptr), -1, false, false,
                        &generator);
        Output output(path);
        KernelTimeline timeline(output, -1, false);
        timeline.set_target_tids({9});
        timeline.set_kernel_span_sink(&generator);

        TraceEvent main_enter = make_event(0, 9, kEventEnter, 1000);
        timeline.on_function_event(main_enter, stack);
        stack.on_event(main_enter);

        KernelEvent out =
            make_kernel_event(CG_KEV_SCHED_SWITCH, CG_KCAT_SCHED, 9, 1100);
        out.peer_tid = 10;
        out.a = 1;  // blocked
        out.b = 120;
        out.c = 120;
        timeline.on_kernel_event(out, stack);

        KernelEvent wake =
            make_kernel_event(CG_KEV_SCHED_WAKEUP, CG_KCAT_SCHED, 9, 1200);
        wake.peer_tid = 0;
        wake.a = 120;
        wake.c = 18;
        timeline.on_kernel_event(wake, stack);

        KernelEvent in =
            make_kernel_event(CG_KEV_SCHED_SWITCH, CG_KCAT_SCHED, 10, 1300);
        in.peer_tid = 9;
        in.a = 0;
        timeline.on_kernel_event(in, stack);

        TraceEvent main_exit = make_event(0, 9, kEventExit, 1400);
        timeline.on_function_event(main_exit, stack);
        stack.on_event(main_exit);
        timeline.finish(1500, stack);
        output.stop();

        const SpanRecord* main = find_span(spans, "main");
        const SpanRecord* off_cpu = find_span(spans, "sched.off_cpu");
        const SpanRecord* runqueue = find_span(spans, "sched.runqueue");
        const SpanRecord* wakeup = find_span(spans, "sched.wakeup");
        CHECK(main != nullptr);
        CHECK(off_cpu != nullptr);
        CHECK(runqueue != nullptr);
        CHECK(wakeup != nullptr);
        if (main && off_cpu && runqueue && wakeup) {
            CHECK(off_cpu->context.parent_span_id == main->context.span_id);
            CHECK(off_cpu->depth == 1);
            CHECK(off_cpu->end_unix_ns - off_cpu->start_unix_ns == 200);
            CHECK(runqueue->context.parent_span_id == off_cpu->context.span_id);
            CHECK(runqueue->depth == 2);
            CHECK(runqueue->end_unix_ns - runqueue->start_unix_ns == 100);
            CHECK(wakeup->context.parent_span_id == off_cpu->context.span_id);
            CHECK(wakeup->depth == 2);
            CHECK(wakeup->start_unix_ns == wakeup->end_unix_ns);
            const SpanAttribute* point =
                find_span_attr(*wakeup, "callgraph.kernel.point");
            CHECK(point != nullptr && point->bool_value);
            const SpanAttribute* user_depth =
                find_span_attr(*off_cpu, "callgraph.kernel.user_depth");
            CHECK(user_depth != nullptr && user_depth->int_value == 0);
        }
    }

    // Page fault point and an unmatched syscall exit.
    {
        SpanGeneratorConfig builder = config();
        builder.seed_hi += 4;
        std::vector<SpanRecord> spans;
        SpanGenerator generator(builder, [&](SpanRecord&& span) {
            spans.push_back(std::move(span));
        });
        CallStack stack(names, static_cast<Output*>(nullptr), -1, false, false,
                        &generator);
        Output output(path);
        KernelTimeline timeline(output, -1, false);
        timeline.set_target_tids({11});
        timeline.set_kernel_span_sink(&generator);

        TraceEvent main_enter = make_event(0, 11, kEventEnter, 2000);
        timeline.on_function_event(main_enter, stack);
        stack.on_event(main_enter);

        KernelEvent fault = make_kernel_event(CG_KEV_PAGE_FAULT_USER,
                                              CG_KCAT_MM, 11, 2100);
        fault.a = 0xdead;
        fault.b = 0xbeef;
        fault.c = 5;
        timeline.on_kernel_event(fault, stack);

        KernelEvent read_end =
            make_kernel_event(CG_KEV_READ_EXIT, CG_KCAT_IO, 11, 2200);
        read_end.a = 0;
        read_end.b = 7;
        timeline.on_kernel_event(read_end, stack);

        TraceEvent main_exit = make_event(0, 11, kEventExit, 2300);
        timeline.on_function_event(main_exit, stack);
        stack.on_event(main_exit);
        timeline.finish(2400, stack);
        output.stop();

        const SpanRecord* main = find_span(spans, "main");
        const SpanRecord* fault_span = find_span(spans, "page_fault.user");
        const SpanRecord* read = find_span(spans, "@read");
        CHECK(main != nullptr);
        CHECK(fault_span != nullptr);
        CHECK(read != nullptr);
        if (main && fault_span && read) {
            CHECK(fault_span->start_unix_ns == fault_span->end_unix_ns);
            CHECK(fault_span->context.parent_span_id == main->context.span_id);
            CHECK(fault_span->depth == 1);
            const SpanAttribute* address =
                find_span_attr(*fault_span, "callgraph.kernel.address");
            const SpanAttribute* user_depth =
                find_span_attr(*fault_span, "callgraph.kernel.user_depth");
            CHECK(address != nullptr && address->string_value == "0xdead");
            CHECK(user_depth != nullptr && user_depth->int_value == 0);

            CHECK(read->start_unix_ns == read->end_unix_ns);
            CHECK(read->context.parent_span_id == main->context.span_id);
            CHECK(read->depth == 1);
            const SpanAttribute* ret =
                find_span_attr(*read, "callgraph.kernel.ret");
            const SpanAttribute* unmatched =
                find_span_attr(*read, "callgraph.kernel.unmatched");
            const SpanAttribute* incomplete =
                find_span_attr(*read, "callgraph.kernel.incomplete");
            const SpanAttribute* event =
                find_span_attr(*read, "callgraph.kernel.event");
            CHECK(ret != nullptr && ret->int_value == 7);
            CHECK(unmatched != nullptr && unmatched->bool_value);
            CHECK(incomplete != nullptr && incomplete->bool_value);
            CHECK(event != nullptr && event->string_value == "read");
        }
    }

    // Nested direct-reclaim intervals.
    {
        SpanGeneratorConfig builder = config();
        builder.seed_hi += 6;
        std::vector<SpanRecord> spans;
        SpanGenerator generator(builder, [&](SpanRecord&& span) {
            spans.push_back(std::move(span));
        });
        CallStack stack(names, static_cast<Output*>(nullptr), -1, false, false,
                        &generator);
        Output output(path);
        KernelTimeline timeline(output, -1, false);
        timeline.set_target_tids({12});
        timeline.set_kernel_span_sink(&generator);

        TraceEvent main_enter = make_event(0, 12, kEventEnter, 3000);
        timeline.on_function_event(main_enter, stack);
        stack.on_event(main_enter);

        KernelEvent begin_outer = make_kernel_event(
            CG_KEV_DIRECT_RECLAIM_BEGIN, CG_KCAT_MM, 12, 3100);
        begin_outer.a = 0;
        begin_outer.b = 0x1;
        timeline.on_kernel_event(begin_outer, stack);
        KernelEvent begin_inner = begin_outer;
        begin_inner.ts = 3200;
        timeline.on_kernel_event(begin_inner, stack);
        KernelEvent end_inner = make_kernel_event(
            CG_KEV_DIRECT_RECLAIM_END, CG_KCAT_MM, 12, 3300);
        end_inner.a = 1;
        timeline.on_kernel_event(end_inner, stack);
        KernelEvent end_outer = end_inner;
        end_outer.ts = 3400;
        end_outer.a = 2;
        timeline.on_kernel_event(end_outer, stack);

        TraceEvent main_exit = make_event(0, 12, kEventExit, 3500);
        timeline.on_function_event(main_exit, stack);
        stack.on_event(main_exit);
        timeline.finish(3600, stack);
        output.stop();

        const SpanRecord* main = find_span(spans, "main");
        const SpanRecord* first = nullptr;
        const SpanRecord* second = nullptr;
        for (const SpanRecord& span : spans) {
            if (span.function.name != "direct_reclaim")
                continue;
            if (!first)
                first = &span;
            else
                second = &span;
        }
        CHECK(main != nullptr);
        CHECK(first != nullptr);
        CHECK(second != nullptr);
        if (main && first && second) {
            const bool first_is_inner =
                first->end_unix_ns - first->start_unix_ns == 100;
            const SpanRecord* inner = first_is_inner ? first : second;
            const SpanRecord* outer = first_is_inner ? second : first;
            CHECK(inner->context.parent_span_id == outer->context.span_id);
            CHECK(inner->end_unix_ns - inner->start_unix_ns == 100);
            CHECK(outer->context.parent_span_id == main->context.span_id);
            CHECK(outer->end_unix_ns - outer->start_unix_ns == 300);
            CHECK(outer->depth == 1);
            CHECK(inner->depth == 2);
        }
    }

    // Scheduler migration and process lifecycle points.
    {
        SpanGeneratorConfig builder = config();
        builder.seed_hi += 8;
        std::vector<SpanRecord> spans;
        SpanGenerator generator(builder, [&](SpanRecord&& span) {
            spans.push_back(std::move(span));
        });
        CallStack stack(names, static_cast<Output*>(nullptr), -1, false, false,
                        &generator);
        Output output(path);
        KernelTimeline timeline(output, -1, false);
        timeline.set_target_tids({13});
        timeline.set_kernel_span_sink(&generator);

        TraceEvent main_enter = make_event(0, 13, kEventEnter, 4000);
        timeline.on_function_event(main_enter, stack);
        stack.on_event(main_enter);

        KernelEvent migrate =
            make_kernel_event(CG_KEV_SCHED_MIGRATE, CG_KCAT_SCHED, 13, 4100);
        migrate.a = 120;
        migrate.b = 1;
        migrate.c = 2;
        timeline.on_kernel_event(migrate, stack);

        KernelEvent fork =
            make_kernel_event(CG_KEV_PROC_FORK, CG_KCAT_SCHED, 13, 4200);
        fork.peer_tid = 14;
        timeline.on_kernel_event(fork, stack);

        KernelEvent process_exit =
            make_kernel_event(CG_KEV_PROC_EXIT, CG_KCAT_SCHED, 13, 4300);
        process_exit.a = 120;
        timeline.on_kernel_event(process_exit, stack);

        timeline.finish(4400, stack);
        stack.finish_spans(4400);
        output.stop();

        const SpanRecord* main = find_span(spans, "main");
        const SpanRecord* migrate_span = find_span(spans, "sched.migrate");
        const SpanRecord* fork_span = find_span(spans, "proc.fork");
        const SpanRecord* exit_span = find_span(spans, "proc.exit");
        CHECK(main != nullptr);
        CHECK(migrate_span != nullptr);
        CHECK(fork_span != nullptr);
        CHECK(exit_span != nullptr);
        if (main && migrate_span && fork_span && exit_span) {
            CHECK(migrate_span->context.parent_span_id == main->context.span_id);
            CHECK(fork_span->context.parent_span_id == main->context.span_id);
            CHECK(exit_span->context.parent_span_id == main->context.span_id);
            CHECK(migrate_span->start_unix_ns == migrate_span->end_unix_ns);
            const SpanAttribute* dest =
                find_span_attr(*migrate_span, "callgraph.kernel.dest_cpu");
            const SpanAttribute* child =
                find_span_attr(*fork_span, "callgraph.kernel.child");
            CHECK(dest != nullptr && dest->int_value == 2);
            CHECK(child != nullptr && child->int_value == 14);
        }
    }

    unlink(path.c_str());
}

void test_kernel_span_depth_clamp()
{
    const std::vector<std::string> names = {"main"};
    std::vector<FunctionMetadata> functions;
    FunctionMetadata metadata;
    metadata.name = "main";
    functions.push_back(metadata);

    SpanGeneratorConfig config;
    config.seed_hi = 31;
    config.seed_lo = 32;
    config.timestamps_are_unix = true;
    config.functions = &functions;

    std::vector<SpanRecord> spans;
    SpanGenerator generator(config, [&](SpanRecord&& span) {
        spans.push_back(std::move(span));
    });
    CallStack stack(names, static_cast<Output*>(nullptr), -1, false, false,
                    &generator);
    const std::string path = temp_path();
    Output output(path);
    KernelTimeline timeline(output, -1, false);
    timeline.set_target_tids({21});
    timeline.set_kernel_span_sink(&generator);

    TraceEvent main_enter = make_event(0, 21, kEventEnter, 100);
    timeline.on_function_event(main_enter, stack);
    stack.on_event(main_enter);

    KernelEvent futex =
        make_kernel_event(CG_KEV_FUTEX_ENTER, CG_KCAT_FUTEX, 21, 200);
    futex.a = 202;
    futex.b = 0x1234;
    futex.c = 0;
    futex.d = 9;
    timeline.on_kernel_event(futex, stack);

    // Simulate a lost/desynced function return while the syscall interval is
    // still open.  The kernel span remains a valid parent, but there is no
    // user frame left, so the user depth must be clamped to zero.
    TraceEvent main_exit = make_event(0, 21, kEventExit, 300);
    timeline.on_function_event(main_exit, stack);
    stack.on_event(main_exit);

    KernelEvent migrate =
        make_kernel_event(CG_KEV_SCHED_MIGRATE, CG_KCAT_SCHED, 21, 400);
    migrate.a = 120;
    migrate.b = 1;
    migrate.c = 2;
    timeline.on_kernel_event(migrate, stack);

    KernelEvent futex_end =
        make_kernel_event(CG_KEV_FUTEX_EXIT, CG_KCAT_FUTEX, 21, 500);
    futex_end.a = 202;
    futex_end.b = 0;
    timeline.on_kernel_event(futex_end, stack);

    timeline.finish(600, stack);
    output.stop();
    unlink(path.c_str());

    const SpanRecord* futex_span = find_span(spans, "@futex");
    const SpanRecord* migrate_span = find_span(spans, "sched.migrate");
    CHECK(futex_span != nullptr);
    CHECK(migrate_span != nullptr);
    if (futex_span && migrate_span) {
        CHECK(migrate_span->context.parent_span_id ==
              futex_span->context.span_id);
        const SpanAttribute* user_depth =
            find_span_attr(*migrate_span, "callgraph.kernel.user_depth");
        CHECK(user_depth != nullptr);
        if (user_depth)
            CHECK(user_depth->int_value == 0);
    }
}

void test_kernel_global_report()
{
    const auto names = make_names();
    const std::string path = temp_path();
    std::string trace;
    std::string report;

    {
        Output output(path);
        CallStack stack(names, output, -1, false, true);
        KernelTimeline timeline(output, -1, false);

        KernelEvent retransmit = {};
        retransmit.ts = 100;
        retransmit.kind = kKernelTcpRetransmit;
        retransmit.category = kKernelCatNet;
        retransmit.a = 1;
        retransmit.b = 1234;
        retransmit.c = 80;
        retransmit.d = 2;
        retransmit.e = 0x0100007f;  // 127.0.0.1
        retransmit.f = 0x0101a8c0;  // 192.168.1.1
        timeline.on_kernel_event(retransmit, stack);

        report = timeline.format_report(names);
        output.stop();
    }
    trace = read_file(path);
    unlink(path.c_str());

    CHECK(trace.find("0 : * @NET tcp_retransmit state=1 sport=1234 dport=80 "
                     "family=2 saddr=127.0.0.1 daddr=192.168.1.1") !=
          std::string::npos);
    CHECK(report.find("  global\n") != std::string::npos);
    CHECK(report.find("NET tcp_retransmit=1") != std::string::npos);
}

}  // namespace

int main()
{
    test_demangle();
    test_errno_string();
    test_latency_histogram();
    test_histogram_report();
    test_histogram_bar_proportional();
    test_histogram_call_path_totals();
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
    test_kernel_memory();
    test_kernel_network();
    test_kernel_histogram_report();
    test_kernel_histogram_roots();
    test_kernel_histogram_incomplete();
    test_kernel_text_ids_without_span_sink();
    test_kernel_span_export();
    test_kernel_span_depth_clamp();
    test_kernel_global_report();
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
    test_trace_duration_histogram();
    test_ingest_sampling_and_log_rate_limit();
    test_outlier_sampling();
    test_outlier_overflow_keeps_duration();
    test_otlp_encoding();
    test_otlp_kernel_span_encoding();
    test_otel_drop_stats();
    test_span_complete_traces();
    test_otel_trace_drop();
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
