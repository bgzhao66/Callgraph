#include <fnmatch.h>
#include <signal.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <unistd.h>

#include <bpf/libbpf_version.h>

#include <algorithm>
#include <cerrno>
#include <cinttypes>
#include <cmath>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <functional>
#include <initializer_list>
#include <iostream>
#include <iterator>
#include <memory>
#include <regex>
#include <string>
#include <unordered_set>
#include <utility>
#include <vector>

#include "callgraph/call_stack.h"
#include "callgraph/common.h"
#include "callgraph/dwarf_args.h"
#include "callgraph/elf_resolver.h"
#include "callgraph/event_collector.h"
#include "callgraph/flame_graph.h"
#include "callgraph/histogram_report.h"
#include "callgraph/kernel_probe_manager.h"
#include "callgraph/kernel_timeline.h"
#include "callgraph/module_manager.h"
#include "callgraph/otel_exporter.h"
#include "callgraph/otlp_json.h"
#include "callgraph/otlp_proto.h"
#include "callgraph/output.h"
#include "callgraph/process_controller.h"
#include "callgraph/probe_manager.h"
#include "callgraph/span_generator.h"
#include "callgraph/static_call_graph.h"
#include "callgraph/static_graph_export.h"
#include "callgraph/static_graph_join.h"
#include "callgraph/static_graph_json.h"
#include "callgraph/clock_converter.h"
#include "callgraph/trace_metadata.h"
#include "callgraph/trace_parser.h"

#include "cli_internal.h"

namespace callgraph {
namespace {

ExportOptions parse_export_args(int argc, char** argv)
{
    if (argc >= 2 && std::string(argv[1]) == "otel") {
        usage_error("the 'otel' token was removed; use "
                    "'callgraph export --otel --input <trace>'");
    }

    ExportOptions options;
    std::vector<std::string> positionals;
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        std::string inline_value;
        bool has_inline_value = false;
        if (arg.rfind("--", 0) == 0) {
            const auto eq = arg.find('=');
            if (eq != std::string::npos) {
                inline_value = arg.substr(eq + 1);
                arg.resize(eq);
                has_inline_value = true;
            }
        }

        auto value = [&]() -> std::string {
            if (has_inline_value)
                return inline_value;
            if (i + 1 >= argc)
                usage_error("option %s requires a value", arg.c_str());
            return argv[++i];
        };
        auto mark_otel_option = [&] { options.otel_option_used = true; };

        if (arg == "--otel") {
            if (options.mode_set && options.mode != ExportMode::Otel)
                usage_error("--otel, --flame, and --static are mutually "
                            "exclusive");
            options.mode = ExportMode::Otel;
            options.mode_set = true;
        } else if (arg == "--flame") {
            if (options.mode_set && options.mode != ExportMode::Flame)
                usage_error("--otel, --flame, and --static are mutually "
                            "exclusive");
            options.mode = ExportMode::Flame;
            options.mode_set = true;
        } else if (arg == "--static") {
            if (options.mode_set && options.mode != ExportMode::Static)
                usage_error("--otel, --flame, and --static are mutually "
                            "exclusive");
            options.mode = ExportMode::Static;
            options.mode_set = true;
        } else if (arg == "--all-modules") {
            usage_error("--all-modules is not valid with export; "
                        "callgraph disasm --all-modules records the whole "
                        "closure in the facts file");
        } else if (arg == "--static-graph") {
            options.static_graph.push_back(value());
            options.static_option_used = true;
        } else if (arg == "--root-scope") {
            options.root_scope.push_back(value());
            options.static_option_used = true;
        } else if (arg == "--regex") {
            options.use_regex = true;
            options.static_option_used = true;
        } else if (arg == "--input") {
            options.input = value();
        } else if (arg == "-o" || arg == "--output") {
            options.output = value();
        } else if (arg == "--endpoint") {
            options.endpoint = value();
            mark_otel_option();
        } else if (arg == "--service-name") {
            options.service_name = value();
            mark_otel_option();
        } else if (arg == "--service-namespace") {
            options.service_namespace = value();
            mark_otel_option();
        } else if (arg == "--metadata") {
            options.metadata_path = value();
            mark_otel_option();
        } else if (arg == "--pid") {
            options.pid = static_cast<pid_t>(parse_long(value(), arg));
            mark_otel_option();
        } else if (arg == "--assume-local-capture") {
            options.assume_local_capture = true;
            mark_otel_option();
        } else if (arg == "--trace-scope") {
            options.trace_scope = value();
            options.trace_scope_set = true;
            mark_otel_option();
        } else if (arg == "--sample-rate") {
            options.sample_rate = parse_fraction(value(), arg);
            mark_otel_option();
        } else if (arg == "--outlier-latency-quantile") {
            options.outlier_latency_quantile = parse_quantile(value(), arg);
            options.outlier_latency_quantile_set = true;
            mark_otel_option();
        } else if (arg == "--show-args") {
            options.show_args = true;
            mark_otel_option();
        } else if (arg == "--trace-id-seed") {
            const std::string seed = value();
            char* end = nullptr;
            options.seed_hi = strtoull(seed.c_str(), &end, 16);
            if (end == seed.c_str() || *end != '\0')
                usage_error("invalid --trace-id-seed '%s'", seed.c_str());
            options.seed_lo = options.seed_hi ^ 0x9e3779b97f4a7c15ULL;
            options.have_seed = true;
            mark_otel_option();
        } else if (arg == "--header") {
            options.headers.push_back(value());
            mark_otel_option();
        } else if (arg == "--batch-size") {
            options.batch_spans = parse_size(value(), arg);
            mark_otel_option();
        } else if (arg == "--batch-bytes") {
            options.batch_bytes = parse_size(value(), arg);
            mark_otel_option();
        } else if (arg == "--flush-interval") {
            options.flush_ms = static_cast<int>(parse_long(value(), arg));
            mark_otel_option();
        } else if (arg == "--timeout-ms") {
            options.timeout_ms = static_cast<int>(parse_long(value(), arg));
            mark_otel_option();
        } else if (arg == "--queue-spans") {
            options.queue_spans = parse_size(value(), arg);
            mark_otel_option();
        } else if (arg == "--compression") {
            options.compression = value();
            mark_otel_option();
        } else if (arg == "--fail-on-export-error") {
            options.fail_on_error = true;
            mark_otel_option();
        } else if (arg == "--complete-traces") {
            options.complete_traces = true;
            mark_otel_option();
        } else if (arg == "--trace-buffer-bytes") {
            options.trace_buffer_bytes = parse_size(value(), arg);
            options.trace_buffer_option_used = true;
            mark_otel_option();
        } else if (arg == "--trace-buffer-spans") {
            options.trace_buffer_spans = parse_size(value(), arg);
            options.trace_buffer_option_used = true;
            mark_otel_option();
        } else if (arg == "-h" || arg == "--help") {
            options.help = true;
        } else if (arg == "--version") {
            options.version = true;
        } else if (arg.rfind("-", 0) == 0) {
            usage_error("unknown export option '%s'", arg.c_str());
        } else {
            positionals.push_back(arg);
        }
    }

    if (options.help) {
        usage_export(stdout, options.mode, options.mode_set);
        std::exit(0);
    }
    if (options.version)
        return options;

    if (!options.mode_set)
        usage_error("export requires --otel, --flame, or --static");

    if (options.mode == ExportMode::Static) {
        if (options.otel_option_used)
            usage_error("OTel options are not valid with --static");
        if (!options.input.empty())
            usage_error("--input is not valid with --static; pass the facts "
                        "file with --static-graph");
        if (!positionals.empty())
            usage_error("export --static takes facts from --static-graph <file>; "
                        "run callgraph disasm <module> instead");
        if (options.static_graph.empty())
            usage_error("export --static requires --static-graph <file> (produce "
                        "it with callgraph disasm)");
        return options;
    }

    if (!positionals.empty())
        usage_error("unexpected export argument '%s'",
                    positionals.front().c_str());
    if (options.static_option_used)
        usage_error("--static-graph, --root-scope, and --regex are only valid "
                    "with --static");

    if (options.mode == ExportMode::Flame) {
        if (options.otel_option_used)
            usage_error("OTel options are not valid with --flame");
        if (options.input.empty())
            usage_error("export --flame requires --input TRACE");
        return options;
    }

    if (options.input.empty())
        usage_error("export --otel requires --input TRACE");
    if (options.output.empty() && options.endpoint.empty())
        usage_error("export --otel requires --output FILE or --endpoint URL");
    if (options.output == "-")
        usage_error("export --otel --output requires a file path, not '-'");
    if (options.trace_buffer_option_used && !options.complete_traces)
        usage_error("--trace-buffer options require --complete-traces");
    if (options.outlier_latency_quantile_set && !options.complete_traces)
        usage_error("--outlier-latency-quantile requires --complete-traces");
    if (options.complete_traces &&
        (options.trace_buffer_bytes == 0 || options.trace_buffer_spans == 0))
        usage_error("--trace-buffer limits must be >= 1");
    if (options.batch_spans == 0 || options.batch_bytes == 0 ||
        options.queue_spans == 0)
        usage_error("batch and queue sizes must be >= 1");
    if (options.flush_ms <= 0 || options.timeout_ms <= 0)
        usage_error("timeouts must be > 0");
    if (options.compression != "none" && options.compression != "gzip")
        usage_error("--compression must be 'none' or 'gzip'");
    TraceScope scope;
    if (!parse_trace_scope(options.trace_scope, &scope))
        usage_error("--trace-scope must be 'root', 'thread', or 'process'");
    if (!options.endpoint.empty() && !otlp_http_available())
        usage_error("--endpoint requires a build with libcurl");
    return options;
}

int run_otel_export(const ExportOptions& options)
{
    TraceMetadata metadata;
    if (!options.metadata_path.empty()) {
        if (!read_trace_metadata(options.metadata_path, &metadata))
            fail("cannot read trace metadata %s",
                 options.metadata_path.c_str());
    }

    const std::string service_name =
        !options.service_name.empty()
            ? options.service_name
            : !metadata.service_name.empty()
                  ? metadata.service_name
                  : "callgraph-import";
    const std::string service_namespace =
        !options.service_namespace.empty() ? options.service_namespace
                                           : metadata.service_namespace;
    const pid_t pid = options.pid > 0 ? options.pid : metadata.pid;
    if (options.assume_local_capture && metadata.present)
        fail("--assume-local-capture cannot be combined with --metadata");
    const bool have_offset =
        options.assume_local_capture || metadata.present;
    uint64_t offset = metadata.monotonic_offset_ns;
    if (options.assume_local_capture) {
        ClockConverter local_clock;
        offset = static_cast<uint64_t>(local_clock.offset_ns());
        log_warn("assuming the trace was captured on this host in the current "
                 "boot session; absolute timestamps are approximate");
    }
    const std::string trace_scope =
        options.trace_scope_set || metadata.trace_scope.empty()
            ? options.trace_scope
            : metadata.trace_scope;

    uint64_t seed_hi = options.have_seed ? options.seed_hi : metadata.seed_hi;
    uint64_t seed_lo = options.have_seed ? options.seed_lo : metadata.seed_lo;
    if (seed_hi == 0 && seed_lo == 0)
        random_seed(&seed_hi, &seed_lo);

    OtelConfig config;
    config.output_path = options.output;
    if (options.endpoint.empty()) {
        config.endpoint.clear();
    } else {
        std::string endpoint = options.endpoint;
        if (!is_http_url(endpoint))
            endpoint = "http://" + endpoint;
        config.endpoint = normalize_otel_endpoint(endpoint);
    }
    config.headers = options.headers;
    config.service_name = service_name;
    config.service_namespace = service_namespace;
    config.service_instance_id =
        !metadata.service_instance_id.empty()
            ? metadata.service_instance_id
            : session_id_hex(seed_hi, seed_lo);
    config.pid = pid;
    config.return_mode = metadata.return_mode;
    config.trace_scope = trace_scope;
    config.attach_mode = metadata.attach_mode;
    config.monotonic_offset_ns = offset;
    config.batch_spans = options.batch_spans;
    config.batch_bytes = options.batch_bytes;
    config.queue_spans = options.queue_spans;
    config.queue_bytes = options.complete_traces ? options.trace_buffer_bytes : 0;
    if (options.complete_traces)
        config.queue_spans =
            std::max(options.queue_spans, options.trace_buffer_spans);
    config.flush_ms = options.flush_ms;
    config.timeout_ms = options.timeout_ms;
    config.gzip = options.compression == "gzip";
    fill_host_otel_config(config);

    OtelExporter exporter(config);
    SpanGeneratorConfig builder_config;
    builder_config.seed_hi = seed_hi;
    builder_config.seed_lo = seed_lo;
    builder_config.timestamps_are_unix = true;
    builder_config.sample_rate = options.sample_rate;
    builder_config.pid = pid;
    builder_config.read_thread_names = false;
    builder_config.complete_traces = options.complete_traces;
    builder_config.outlier_quantile = options.outlier_latency_quantile;
    builder_config.trace_buffer_bytes = options.trace_buffer_bytes;
    builder_config.trace_buffer_spans = options.trace_buffer_spans;
    std::vector<FunctionMetadata> functions;
    builder_config.functions = &functions;
    if (!parse_trace_scope(trace_scope, &builder_config.scope))
        builder_config.scope = TraceScope::Root;

    SpanGenerator builder(
        builder_config,
        [&exporter](SpanRecord&& span) {
            exporter.export_span(std::move(span));
        },
        [&exporter](std::vector<SpanRecord>&& spans) {
            exporter.export_trace(std::move(spans));
        });

    std::vector<std::string> names;
    CallStack stack(names, static_cast<Output*>(nullptr), -1, false, false,
                    &builder);

    TraceParseOptions parse_options;
    parse_options.show_args = options.show_args;
    parse_options.have_monotonic_offset = have_offset;
    parse_options.monotonic_offset_ns = offset;

    uint64_t last_ts = 0;
    const TraceParseStats stats = parse_text_trace(
        options.input, stack, names, functions, &metadata, parse_options,
        &last_ts);

    if (stats.event_lines == 0)
        fail("no callgraph events found in %s", options.input.c_str());

    stack.finish_spans(last_ts);
    exporter.finish();

    fprintf(stderr,
            "callgraph: converted %" PRIu64 " events (%" PRIu64
            " entries, %" PRIu64 " returns), %" PRIu64 " OTLP span(s), "
            "%" PRIu64 " dropped, %" PRIu64 " failed\n",
            stats.event_lines, stats.entries, stats.exits,
            exporter.exported(), exporter.dropped(), exporter.failed());
    print_otel_drop_stats(exporter);
    if (options.complete_traces)
        print_trace_buffer_stats(builder);
    print_outlier_stats(builder);

    return exporter.failed() != 0 && options.fail_on_error ? 1 : 0;
}

int run_flame_export(const ExportOptions& options)
{
    std::vector<std::string> names;
    std::vector<FunctionMetadata> functions;
    FlameGraphSink sink(functions);

    CallStack stack(names, static_cast<Output*>(nullptr), -1, false, false,
                    &sink);

    TraceParseOptions parse_options;
    parse_options.require_timestamp_anchor = false;

    uint64_t last_ts = 0;
    const TraceParseStats stats = parse_text_trace(
        options.input, stack, names, functions, nullptr, parse_options,
        &last_ts);

    if (stats.event_lines == 0)
        fail("no callgraph events found in %s", options.input.c_str());

    stack.finish_spans(last_ts);
    const std::string folded = sink.render();

    if (options.output.empty() || options.output == "-") {
        const size_t written = fwrite(folded.data(), 1, folded.size(), stdout);
        if (written != folded.size())
            fail("cannot write folded stacks to stdout");
        fflush(stdout);
    } else {
        std::ofstream output(options.output, std::ios::binary);
        if (!output) {
            fail("cannot open %s for writing", options.output.c_str());
        }
        output.write(folded.data(), static_cast<std::streamsize>(folded.size()));
        if (!output) {
            fail("cannot write folded stacks to %s", options.output.c_str());
        }
    }

    fprintf(stderr,
            "callgraph: converted %" PRIu64 " events into %" PRIu64
            " folds (%zu unique stacks)\n",
            stats.event_lines, sink.recorded(), sink.unique_stacks());
    return 0;
}

int run_static_export(const ExportOptions& options);

int run_export(const ExportOptions& options)
{
    if (options.mode == ExportMode::Flame)
        return run_flame_export(options);
    if (options.mode == ExportMode::Static)
        return run_static_export(options);
    return run_otel_export(options);
}

int run_static_export(const ExportOptions& options)
{
    StaticGraphDocument document;
    load_static_graphs(options.static_graph, &document);
    if (document.modules.empty())
        fail("--static-graph contains no modules");

    FunctionFilter filter(options.root_scope, {}, options.use_regex);

    std::ofstream file;
    std::ostream* out = &std::cout;
    if (!options.output.empty() && options.output != "-") {
        file.open(options.output, std::ios::binary);
        if (!file)
            fail("cannot open %s for writing", options.output.c_str());
        out = &file;
    }

    const bool multi_module = document.modules.size() > 1;
    size_t roots_written = 0;
    size_t modules_written = 0;

    for (size_t index = 0; index < document.modules.size(); ++index) {
        StaticGraphModule& module = document.modules[index];
        const bool primary = index == 0;

        if (!module.prunable) {
            const std::string reason = module.prune_reason.empty()
                                           ? "call graph is unavailable"
                                           : module.prune_reason;
            if (primary)
                fail("cannot render a static call graph for %s: %s",
                     module.path.c_str(), reason.c_str());
            log_warn("skipping module %s: %s", module.path.c_str(),
                     reason.c_str());
            continue;
        }

        std::vector<size_t> roots;
        if (filter.has_root_scope()) {
            for (size_t i = 0; i < module.functions.size(); ++i) {
                if (filter.root_match_name(module.functions[i].name,
                                           module.functions[i].linkage_name))
                    roots.push_back(i);
            }
            if (roots.empty()) {
                if (primary)
                    fail("no function in %s matches --root-scope",
                         module.path.c_str());
                log_verbose("skipping module %s: no --root-scope match",
                            module.path.c_str());
                continue;
            }
        } else {
            roots = static_graph_module_roots(module);
            if (roots.empty()) {
                if (primary)
                    fail("no call-graph roots found in %s",
                         module.path.c_str());
                log_verbose("skipping module %s: no call-graph roots",
                            module.path.c_str());
                continue;
            }
        }
        module.roots = std::move(roots);

        if (multi_module) {
            if (modules_written > 0)
                *out << '\n';
            *out << "== " << module.path << " ==\n";
        }
        write_static_graph(module, *out);
        roots_written += module.roots.size();
        ++modules_written;
    }

    out->flush();
    if (!*out) {
        if (out == &std::cout)
            fail("cannot write static call graph to stdout");
        fail("cannot write static call graph to %s", options.output.c_str());
    }

    fprintf(stderr,
            "callgraph: static graph: %zu root(s) in %zu module(s)\n",
            roots_written, modules_written);
    return 0;
}

}  // namespace

int export_program(int argc, char** argv)
{
    try {
        set_program_mode(argv[0], ProgramMode::Export);
        const ExportOptions options = parse_export_args(argc, argv);
        if (options.version) {
            print_version();
            return 0;
        }
        return run_export(options);
    } catch (const std::exception& error) {
        fprintf(stderr, "%s: %s\n", program_name(), error.what());
        return 1;
    }
}

}  // namespace callgraph
