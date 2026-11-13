#include <fnmatch.h>
#include <signal.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <unistd.h>

#include <bpf/libbpf_version.h>

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
#include "callgraph/module_manager.h"
#include "callgraph/otel_exporter.h"
#include "callgraph/otlp_json.h"
#include "callgraph/otlp_proto.h"
#include "callgraph/output.h"
#include "callgraph/process_controller.h"
#include "callgraph/probe_manager.h"
#include "callgraph/span_generator.h"
#include "callgraph/clock_converter.h"
#include "callgraph/trace_metadata.h"
#include "callgraph/trace_parser.h"

namespace callgraph {
volatile sig_atomic_t g_stop = 0;
}

using namespace callgraph;

namespace {

struct Options {
    std::string command;
    pid_t pid = -1;
    std::string output;
    std::vector<std::string> include;
    std::vector<std::string> exclude;
    bool use_regex = false;
    std::string return_mode = "uretprobe";
    bool all_modules = false;
    std::vector<std::string> modules;
    bool wall_clock = false;
    int max_depth = -1;
    size_t indent_step = 0;
    bool show_args = false;
    bool histogram = false;
    size_t probe_batch_size = 1000;
    size_t ringbuf_size = 16ull << 20;
    bool dry_run = false;
    bool verbose = false;
    bool help = false;
    bool version = false;
    std::vector<std::string> program;

    std::string exporter;
    bool exporter_set = false;
    bool export_option_used = false;
    bool endpoint_set = false;
    bool export_file_set = false;
    std::string endpoint;
    std::string export_file;
    std::string service_name;
    std::string service_namespace;
    std::string trace_scope = "root";
    std::vector<std::string> headers;
    size_t batch_size = 512;
    size_t batch_bytes = 1ull << 20;
    size_t queue_spans = 10000;
    int flush_interval_ms = 1000;
    int timeout_ms = 5000;
    std::string compression = "none";
    bool fail_on_export_error = false;
    double sample_rate = 1.0;
    std::string trace_metadata;
};

enum class UsageMode { Run, Export };
UsageMode g_usage_mode = UsageMode::Run;

void usage(FILE* out)
{
    fprintf(out,
            "Usage:\n"
            "  callgraph run [options] -- program [args...]\n"
            "  callgraph attach [options] -p PID\n"
            "  callgraph export --otel|--flame --input TRACE [options]\n"
            "\n"
            "Options:\n"
            "  -o, --output FILE     write events to FILE (default: stdout)\n"
            "      --include GLOB    only trace functions matching GLOB (repeatable)\n"
            "      --exclude GLOB    skip functions matching GLOB (repeatable)\n"
            "      --regex           treat --include/--exclude as extended regex\n"
            "      --return-mode M   uretprobe (default) or ret (exception-safe)\n"
            "      --all-modules     trace every mapped ELF module\n"
            "      --module GLOB     also trace mapped modules matching GLOB\n"
            "  -T, --wall-clock      wall-clock timestamps (default: seconds since boot)\n"
            "      --max-depth N     print events with depth <= N (default: unlimited)\n"
            "      --indent N        indent names by depth*N spaces (default: 0)\n"
            "      --show-args       show function arguments after names (needs DWARF)\n"
            "      --histogram       append a per-thread call tree and latency histograms to the output\n"
            "      --probe-batch-size N  functions per uprobe_multi link (default: 1000)\n"
            "      --ringbuf-size N  ring buffer size, k/m/g suffix (default: 16m)\n"
            "      --dry-run         list resolved functions and exit\n"
            "      --exporter M      stdout (default), otlp, otlp-http, or otlp-json\n"
            "      --endpoint URL    OTLP endpoint; default localhost:4317 / :4318\n"
            "      --export-file FILE  output file for --exporter otlp-json\n"
            "      --service-name NAME\n"
            "                        override service.name (default: exe basename)\n"
            "      --service-namespace NAME\n"
            "      --trace-scope M   root (default), thread, or process\n"
            "      --batch-size N    spans per OTLP batch (default: 512)\n"
            "      --batch-bytes N   OTLP request size limit (default: 1m)\n"
            "      --flush-interval N  OTLP batch flush interval in ms (default: 1000)\n"
            "      --timeout-ms N    OTLP HTTP timeout (default: 5000)\n"
            "      --queue-spans N   exporter queue limit (default: 10000)\n"
            "      --header K=V      add an HTTP header (repeatable)\n"
            "      --compression M   none (default) or gzip (OTLP/HTTP only)\n"
            "      --sample-rate R   root-trace sampling rate, 0..1 (default: 1)\n"
            "      --fail-on-export-error  exit non-zero if export fails\n"
            "      --trace-metadata FILE  write an offline-conversion sidecar\n"
            "  -v, --verbose         verbose diagnostics\n"
            "  -h, --help            show this help\n"
            "      --version         show version\n"
            "\n"
            "Examples:\n"
            "  sudo callgraph run -- ./demo\n"
            "  sudo callgraph attach -p 12345 --include 'Database::*'\n"
            "  callgraph run --dry-run -- ./demo\n"
            "  sudo callgraph run --exporter otlp --endpoint localhost:4317 -- ./demo\n"
            "  sudo callgraph run --exporter otlp-http -- ./demo\n"
            "  sudo callgraph run --exporter otlp-json --export-file trace.json -- ./demo\n"
            "  sudo callgraph attach -p 12345 --exporter otlp \\\n"
            "      --endpoint localhost:4317 --service-name my_app\n"
            "  callgraph export --otel --input trace.log --output spans.json\n"
            "  callgraph export --flame --input trace.log --output stacks.folded\n"
            "\n"
            "Run 'callgraph export --help' for offline conversion options.\n");
}

void export_usage(FILE* out)
{
    fprintf(out,
            "Usage:\n"
            "  callgraph export --otel --input TRACE [options]\n"
            "  callgraph export --flame --input TRACE [options]\n"
            "\n"
            "Modes:\n"
            "  --otel    convert a text trace to OpenTelemetry OTLP/JSON spans\n"
            "  --flame   convert a text trace to folded stacks for flame graphs\n"
            "\n"
            "Shared options:\n"
            "  --input FILE          callgraph text trace to convert\n"
            "  -o, --output FILE     write output to FILE\n"
            "  -h, --help            show this help\n"
            "\n"
            "Mode-specific help:\n"
            "  callgraph export --otel --help\n"
            "  callgraph export --flame --help\n");
}

void otel_export_usage(FILE* out)
{
    fprintf(out,
            "Usage:\n"
            "  callgraph export --otel --input TRACE [options]\n"
            "\n"
            "Convert a callgraph text trace into OpenTelemetry spans.  The\n"
            "offline command emits one OTLP/JSON request body; use -o/--output\n"
            "to write it to a file or --endpoint to POST it to an OTLP/HTTP\n"
            "JSON receiver.\n"
            "\n"
            "Options:\n"
            "  --input FILE          callgraph text trace to convert\n"
            "  -o, --output FILE     write the OTLP/JSON request body to FILE\n"
            "  --endpoint URL        POST the OTLP/JSON body to URL\n"
            "                        (OTLP/HTTP JSON; path defaults to /v1/traces)\n"
            "  --service-name NAME   override service.name\n"
            "  --service-namespace NAME\n"
            "  --metadata FILE       trace metadata sidecar\n"
            "  --assume-local-capture  assume the trace came from this host/boot session\n"
            "  --trace-scope MODE    root (default), thread, or process\n"
            "  --trace-id-seed HEX   deterministic trace IDs\n"
            "  --sample-rate R       root-trace sampling rate, 0..1\n"
            "  --batch-size N        spans per OTLP batch (default: 512)\n"
            "  --batch-bytes N       request size limit (default: 1m)\n"
            "  --flush-interval N    batch flush interval in ms (default: 1000)\n"
            "  --timeout-ms N        HTTP timeout (default: 5000)\n"
            "  --queue-spans N       exporter queue limit (default: 10000)\n"
            "  --header K=V          add an HTTP header (repeatable)\n"
            "  --compression M       none (default) or gzip\n"
            "  --fail-on-export-error  exit non-zero if export fails\n"
            "  --input-show-args     preserve --show-args suffixes as attributes\n"
            "  -h, --help            show this help\n"
            "\n"
            "Notes:\n"
            "  --output and --endpoint are alternatives; one is required.\n"
            "  This command emits OTLP/JSON only. For live OTLP/gRPC or\n"
            "  OTLP/HTTP-protobuf use --exporter otlp or --exporter otlp-http.\n"
            "\n"
            "Examples:\n"
            "  # Preferred: record the anchor while capturing\n"
            "  callgraph run -o trace.log --trace-metadata trace.meta -- ./app\n"
            "  callgraph export --otel --input trace.log \\\n"
            "      --metadata trace.meta --output spans.json\n"
            "\n"
            "  # Trace with -T (ISO wall-clock timestamps), no sidecar\n"
            "  callgraph export --otel --input trace.log --output spans.json\n"
            "\n"
            "  # Boot-second trace with no sidecar; approximate this-host anchor\n"
            "  callgraph export --otel --input trace.log --output spans.json \\\n"
            "      --assume-local-capture\n");
}

void flame_export_usage(FILE* out)
{
    fprintf(out,
            "Usage:\n"
            "  callgraph export --flame --input TRACE [options]\n"
            "\n"
            "Convert a callgraph text trace into folded stacks for\n"
            "flamegraph.pl or inferno-flamegraph.  Output goes to stdout unless\n"
            "-o/--output is given.\n"
            "\n"
            "Options:\n"
            "  --input FILE          callgraph text trace to convert\n"
            "  -o, --output FILE     write folded stacks to FILE (default: stdout)\n"
            "  -h, --help            show this help\n"
            "\n"
            "Format:\n"
            "  main;C(int);B(int) 1\n"
            "  main;C(int) 1\n"
            "  main 1\n"
            "\n"
            "Each line is a root-to-function stack followed by its invocation\n"
            "count. Frames closed by desync or shutdown end in [incomplete].\n"
            "\n"
            "Example:\n"
            "  callgraph export --flame --input trace.log --output stacks.folded\n"
            "  flamegraph.pl stacks.folded > flame.svg\n");
}

[[noreturn]] void usage_error(const char* fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    fprintf(stderr, "callgraph: ");
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n\n");
    va_end(ap);
    if (g_usage_mode == UsageMode::Export)
        export_usage(stderr);
    else
        usage(stderr);
    std::exit(2);
}

long parse_long(const std::string& text, const std::string& option)
{
    char* end = nullptr;
    errno = 0;
    const long value = strtol(text.c_str(), &end, 10);
    if (errno != 0 || end == text.c_str() || *end != '\0')
        usage_error("invalid value for %s: '%s'", option.c_str(), text.c_str());
    return value;
}

size_t parse_size(const std::string& text, const std::string& option)
{
    char* end = nullptr;
    errno = 0;
    unsigned long long value = strtoull(text.c_str(), &end, 0);
    if (errno != 0 || end == text.c_str())
        usage_error("invalid value for %s: '%s'", option.c_str(), text.c_str());

    switch (*end) {
    case 'k':
    case 'K':
        value <<= 10;
        ++end;
        break;
    case 'm':
    case 'M':
        value <<= 20;
        ++end;
        break;
    case 'g':
    case 'G':
        value <<= 30;
        ++end;
        break;
    default:
        break;
    }

    if (*end != '\0')
        usage_error("invalid value for %s: '%s'", option.c_str(), text.c_str());
    return static_cast<size_t>(value);
}

Options parse_args(int argc, char** argv)
{
    Options options;
    if (argc < 2)
        usage_error("missing command");

    options.command = argv[1];
    if (options.command == "-h" || options.command == "--help") {
        options.help = true;
        return options;
    }
    if (options.command == "--version") {
        options.version = true;
        return options;
    }
    if (options.command != "run" && options.command != "attach")
        usage_error("unknown command '%s'", options.command.c_str());

    for (int i = 2; i < argc; ++i) {
        std::string arg = argv[i];

        if (options.command == "run" && arg == "--") {
            for (++i; i < argc; ++i)
                options.program.emplace_back(argv[i]);
            break;
        }

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
        auto mark_export_option = [&] { options.export_option_used = true; };

        if (arg == "-o" || arg == "--output") {
            options.output = value();
        } else if (arg == "--include") {
            options.include.push_back(value());
        } else if (arg == "--exclude") {
            options.exclude.push_back(value());
        } else if (arg == "--regex") {
            options.use_regex = true;
        } else if (arg == "--return-mode") {
            options.return_mode = value();
            if (options.return_mode != "uretprobe" && options.return_mode != "ret")
                usage_error("--return-mode must be 'uretprobe' or 'ret'");
        } else if (arg == "--all-modules") {
            options.all_modules = true;
        } else if (arg == "--module") {
            options.modules.push_back(value());
        } else if (arg == "-T" || arg == "--wall-clock") {
            options.wall_clock = true;
        } else if (arg == "--max-depth") {
            options.max_depth = static_cast<int>(parse_long(value(), arg));
        } else if (arg == "--indent") {
            const long indent = parse_long(value(), arg);
            if (indent < 0)
                usage_error("--indent must be >= 0");
            options.indent_step = static_cast<size_t>(indent);
        } else if (arg == "--show-args") {
            options.show_args = true;
        } else if (arg == "--histogram") {
            options.histogram = true;
        } else if (arg == "--probe-batch-size") {
            options.probe_batch_size = parse_size(value(), arg);
        } else if (arg == "--ringbuf-size") {
            options.ringbuf_size = parse_size(value(), arg);
        } else if (arg == "--dry-run") {
            options.dry_run = true;
        } else if (arg == "--exporter") {
            options.exporter = value();
            options.exporter_set = true;
        } else if (arg == "--endpoint") {
            options.endpoint = value();
            options.endpoint_set = true;
            mark_export_option();
        } else if (arg == "--export-file") {
            options.export_file = value();
            options.export_file_set = true;
            mark_export_option();
        } else if (arg == "--service-name") {
            options.service_name = value();
            mark_export_option();
        } else if (arg == "--service-namespace") {
            options.service_namespace = value();
            mark_export_option();
        } else if (arg == "--trace-scope") {
            options.trace_scope = value();
            mark_export_option();
        } else if (arg == "--batch-size") {
            options.batch_size = parse_size(value(), arg);
            mark_export_option();
        } else if (arg == "--batch-bytes") {
            options.batch_bytes = parse_size(value(), arg);
            mark_export_option();
        } else if (arg == "--flush-interval") {
            options.flush_interval_ms =
                static_cast<int>(parse_long(value(), arg));
            mark_export_option();
        } else if (arg == "--timeout-ms") {
            options.timeout_ms = static_cast<int>(parse_long(value(), arg));
            mark_export_option();
        } else if (arg == "--queue-spans") {
            options.queue_spans = parse_size(value(), arg);
            mark_export_option();
        } else if (arg == "--header") {
            options.headers.push_back(value());
            mark_export_option();
        } else if (arg == "--compression") {
            options.compression = value();
            mark_export_option();
        } else if (arg == "--sample-rate") {
            const std::string rate = value();
            char* end = nullptr;
            errno = 0;
            options.sample_rate = strtod(rate.c_str(), &end);
            if (errno != 0 || end == rate.c_str() || *end != '\0' ||
                !std::isfinite(options.sample_rate) ||
                options.sample_rate < 0.0 || options.sample_rate > 1.0) {
                usage_error("--sample-rate must be between 0 and 1");
            }
            mark_export_option();
        } else if (arg == "--fail-on-export-error") {
            options.fail_on_export_error = true;
            mark_export_option();
        } else if (arg == "--trace-metadata") {
            options.trace_metadata = value();
        } else if (arg == "-v" || arg == "--verbose") {
            options.verbose = true;
        } else if (arg == "-p" || arg == "--pid") {
            options.pid = static_cast<pid_t>(parse_long(value(), arg));
        } else if (arg == "-h" || arg == "--help") {
            options.help = true;
            return options;
        } else if (arg == "--version") {
            options.version = true;
            return options;
        } else if (!arg.empty() && arg[0] == '-') {
            usage_error("unknown option '%s'", arg.c_str());
        } else if (options.command == "run") {
            options.program.push_back(arg);
            for (++i; i < argc; ++i)
                options.program.emplace_back(argv[i]);
            break;
        } else {
            usage_error("unexpected argument '%s'", arg.c_str());
        }
    }

    if (options.command == "run" && options.program.empty())
        usage_error("run requires a program (use -- before it)");
    if (options.command == "attach" && options.pid <= 0)
        usage_error("attach requires -p PID");
    if (options.max_depth < -1)
        usage_error("--max-depth must be >= -1");
    if (options.probe_batch_size == 0)
        usage_error("--probe-batch-size must be >= 1");
    if (options.batch_size == 0 || options.batch_bytes == 0 ||
        options.queue_spans == 0)
        usage_error("OTLP batch and queue sizes must be >= 1");
    if (options.flush_interval_ms <= 0 || options.timeout_ms <= 0)
        usage_error("OTLP timeouts must be > 0");
    if (options.compression != "none" && options.compression != "gzip")
        usage_error("--compression must be 'none' or 'gzip'");
    TraceScope trace_scope_mode;
    if (!parse_trace_scope(options.trace_scope, &trace_scope_mode))
        usage_error("--trace-scope must be 'root', 'thread', or 'process'");

    if (!options.exporter_set && options.export_option_used)
        usage_error("export options require --exporter (stdout is the default)");

    const std::string exporter_mode =
        options.exporter_set ? options.exporter : "stdout";
    if (exporter_mode != "stdout" && exporter_mode != "otlp" &&
        exporter_mode != "otlp-http" && exporter_mode != "otlp-json") {
        usage_error("--exporter must be 'stdout', 'otlp', 'otlp-http', or "
                    "'otlp-json'");
    }
    if (exporter_mode == "stdout" && options.export_option_used)
        usage_error("export options are not valid with --exporter stdout");
    if (exporter_mode == "otlp" || exporter_mode == "otlp-http") {
        if (!otlp_http_available())
            usage_error("--exporter %s requires a build with libcurl",
                        exporter_mode.c_str());
        if (!otlp_protobuf_available())
            usage_error("--exporter %s requires OTLP protobuf support",
                        exporter_mode.c_str());
        if (options.export_file_set)
            usage_error("--export-file is only valid with --exporter otlp-json");
    }
    if (exporter_mode == "otlp" && options.compression == "gzip")
        usage_error("gzip is only supported for --exporter otlp-http");
    if (exporter_mode == "otlp-json") {
        if (options.export_file.empty())
            usage_error("--exporter otlp-json requires --export-file FILE");
        if (options.endpoint_set)
            usage_error("--endpoint is not used by --exporter otlp-json");
        if (!options.headers.empty())
            usage_error("--header is not used by --exporter otlp-json");
        if (options.compression != "none")
            usage_error("--compression is not used by --exporter otlp-json");
    }
    if (!options.export_file.empty() && options.export_file == "-")
        usage_error("--export-file requires a file path, not '-'");
    if (!options.export_file.empty() && options.export_file == options.output)
        usage_error("--export-file and --output must not name the same file");
    if (!options.trace_metadata.empty() &&
        (options.trace_metadata == options.output ||
         options.trace_metadata == options.export_file))
        usage_error("--trace-metadata must not share a path with output");
#ifndef CALLGRAPH_HAVE_LIBOPCODES
    if (options.return_mode == "ret")
        usage_error("--return-mode=ret requires libopcodes (install binutils-dev "
                    "and rebuild)");
#endif
#if !defined(__x86_64__)
    if (options.show_args)
        usage_error("--show-args is only supported on x86-64");
#endif

    const long page_size = sysconf(_SC_PAGESIZE);
    const size_t rb = options.ringbuf_size;
    if (rb < 4096 || (rb & (rb - 1)) != 0 ||
        (page_size > 0 && rb % static_cast<size_t>(page_size) != 0))
        usage_error("--ringbuf-size must be a power of two and a multiple of "
                    "the page size");

    return options;
}

std::string executable_basename(const std::string& path)
{
    return std::filesystem::path(path).filename().string();
}

std::string read_command_line(pid_t pid)
{
    if (pid <= 0)
        return {};
    std::ifstream input("/proc/" + std::to_string(pid) + "/cmdline");
    if (!input)
        return {};
    std::string value((std::istreambuf_iterator<char>(input)),
                      std::istreambuf_iterator<char>());
    for (char& c : value) {
        if (c == '\0')
            c = ' ';
    }
    while (!value.empty() && value.back() == ' ')
        value.pop_back();
    return value;
}

std::string join_program(const std::vector<std::string>& program)
{
    std::string line;
    for (size_t i = 0; i < program.size(); ++i) {
        if (i != 0)
            line.push_back(' ');
        line += program[i];
    }
    return line;
}

std::string session_id_hex(uint64_t hi, uint64_t lo)
{
    char buffer[40];
    snprintf(buffer, sizeof(buffer), "%016" PRIx64 "%016" PRIx64, hi, lo);
    return buffer;
}

std::string normalize_otel_endpoint(std::string endpoint)
{
    const size_t scheme = endpoint.find("://");
    const size_t path_start =
        scheme == std::string::npos ? std::string::npos
                                    : endpoint.find('/', scheme + 3);
    if (path_start == std::string::npos) {
        if (!endpoint.empty() && endpoint.back() != '/')
            endpoint.push_back('/');
        endpoint += "v1/traces";
    } else if (path_start + 1 == endpoint.size()) {
        endpoint += "v1/traces";
    }
    return endpoint;
}

bool is_http_url(const std::string& endpoint)
{
    return endpoint.rfind("http://", 0) == 0 ||
           endpoint.rfind("https://", 0) == 0;
}

void fill_host_otel_config(OtelConfig& config)
{
    struct utsname uts = {};
    if (uname(&uts) == 0) {
        config.host_name = uts.nodename;
        config.host_arch = uts.machine;
        config.os_description = uts.release;
    }
    config.tool_version = CALLGRAPH_VERSION;
}

enum class ExportMode { Otel, Flame };

struct ExportOptions {
    std::string input;
    std::string output;
    ExportMode mode = ExportMode::Otel;
    bool mode_set = false;
    bool help = false;
    bool otel_option_used = false;
    std::string endpoint;
    std::string service_name;
    std::string service_namespace;
    std::string metadata_path;
    pid_t pid = 0;
    bool assume_local_capture = false;
    std::string trace_scope = "root";
    bool trace_scope_set = false;
    double sample_rate = 1.0;
    bool input_show_args = false;
    bool have_seed = false;
    uint64_t seed_hi = 0;
    uint64_t seed_lo = 0;
    std::vector<std::string> headers;
    size_t batch_spans = 512;
    size_t batch_bytes = 1ull << 20;
    size_t queue_spans = 10000;
    int flush_ms = 1000;
    int timeout_ms = 5000;
    std::string compression = "none";
    bool fail_on_error = false;
};

ExportOptions parse_export_args(int argc, char** argv)
{
    g_usage_mode = UsageMode::Export;
    if (argc >= 3 && std::string(argv[2]) == "otel") {
        usage_error("the 'otel' token was removed; use "
                    "'callgraph export --otel --input TRACE'");
    }

    ExportOptions options;
    for (int i = 2; i < argc; ++i) {
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
                usage_error("--otel and --flame are mutually exclusive");
            options.mode = ExportMode::Otel;
            options.mode_set = true;
        } else if (arg == "--flame") {
            if (options.mode_set && options.mode != ExportMode::Flame)
                usage_error("--otel and --flame are mutually exclusive");
            options.mode = ExportMode::Flame;
            options.mode_set = true;
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
            const std::string rate = value();
            char* end = nullptr;
            errno = 0;
            options.sample_rate = strtod(rate.c_str(), &end);
            if (errno != 0 || end == rate.c_str() || *end != '\0' ||
                !std::isfinite(options.sample_rate) ||
                options.sample_rate < 0.0 || options.sample_rate > 1.0) {
                usage_error("--sample-rate must be between 0 and 1");
            }
            mark_otel_option();
        } else if (arg == "--input-show-args") {
            options.input_show_args = true;
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
        } else if (arg == "-h" || arg == "--help") {
            options.help = true;
        } else {
            usage_error("unknown export option '%s'", arg.c_str());
        }
    }

    if (options.help) {
        if (!options.mode_set)
            export_usage(stdout);
        else if (options.mode == ExportMode::Otel)
            otel_export_usage(stdout);
        else
            flame_export_usage(stdout);
        std::exit(0);
    }

    if (!options.mode_set)
        usage_error("export requires --otel or --flame");

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
    std::vector<FunctionMetadata> functions;
    builder_config.functions = &functions;
    if (!parse_trace_scope(trace_scope, &builder_config.scope))
        builder_config.scope = TraceScope::Root;

    SpanGenerator builder(builder_config, [&exporter](SpanRecord&& span) {
        exporter.export_span(std::move(span));
    });

    std::vector<std::string> names;
    CallStack stack(names, static_cast<Output*>(nullptr), -1, false, false,
                    &builder);

    TraceParseOptions parse_options;
    parse_options.input_show_args = options.input_show_args;
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
            "%" PRIu64 " failed\n",
            stats.event_lines, stats.entries, stats.exits,
            exporter.exported(), exporter.failed());

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

int run_export(const ExportOptions& options)
{
    if (options.mode == ExportMode::Flame)
        return run_flame_export(options);
    return run_otel_export(options);
}

class FunctionFilter {
public:
    FunctionFilter(const std::vector<std::string>& include,
                   const std::vector<std::string>& exclude, bool use_regex)
        : include_(include), exclude_(exclude), use_regex_(use_regex)
    {
        if (use_regex_) {
            try {
                for (const auto& pattern : include_)
                    include_re_.emplace_back(pattern);
                for (const auto& pattern : exclude_)
                    exclude_re_.emplace_back(pattern);
            } catch (const std::regex_error& error) {
                fail("invalid regular expression: %s", error.what());
            }
        }
    }

    bool keep(const FunctionInfo& function) const
    {
        if (!include_.empty() && !matches(function, include_, include_re_))
            return false;
        if (!exclude_.empty() && matches(function, exclude_, exclude_re_))
            return false;
        return true;
    }

private:
    static bool matches(const FunctionInfo& function,
                        const std::vector<std::string>& globs,
                        const std::vector<std::regex>& regexes)
    {
        for (const auto& pattern : globs) {
            if (fnmatch(pattern.c_str(), function.name.c_str(), 0) == 0)
                return true;
            if (fnmatch(pattern.c_str(), function.linkage_name.c_str(), 0) == 0)
                return true;
        }
        for (const auto& regex : regexes) {
            if (std::regex_search(function.name, regex))
                return true;
            if (std::regex_search(function.linkage_name, regex))
                return true;
        }
        return false;
    }

    std::vector<std::string> include_;
    std::vector<std::string> exclude_;
    bool use_regex_;
    std::vector<std::regex> include_re_;
    std::vector<std::regex> exclude_re_;
};

bool module_matches(const std::string& path,
                    const std::vector<std::string>& globs)
{
    if (globs.empty())
        return false;

    const auto slash = path.find_last_of('/');
    const std::string base =
        slash == std::string::npos ? path : path.substr(slash + 1);

    for (const auto& glob : globs) {
        if (fnmatch(glob.c_str(), path.c_str(), 0) == 0)
            return true;
        if (fnmatch(glob.c_str(), base.c_str(), 0) == 0)
            return true;
    }
    return false;
}

struct PlannedModule {
    std::string path;
    std::vector<FunctionInfo> functions;
};

// Resolves, filters, numbers, and (when probes != nullptr) attaches modules.
// Dynamic discovery calls add() from the collector thread, so names_ may grow
// while CallStack holds a reference to it; the vector object itself is stable.
class ModuleRegistry {
public:
    ModuleRegistry(const Options& options, FunctionFilter& filter,
                   ProbeManager* probes, bool ret_mode)
        : options_(options), filter_(filter), probes_(probes),
          ret_mode_(ret_mode)
    {
    }

    bool add(const std::string& path, bool required)
    {
        if (!attached_.insert(path).second)
            return true;

        ModuleInfo module;
        try {
            module = ElfResolver::resolve(path);
        } catch (const std::exception& error) {
            if (required)
                fail("cannot resolve %s: %s", path.c_str(), error.what());
            log_verbose("skipping %s: %s", path.c_str(), error.what());
            return false;
        }

        std::vector<FunctionInfo> selected;
        selected.reserve(module.functions.size());
        for (auto& function : module.functions) {
            if (filter_.keep(function))
                selected.push_back(std::move(function));
        }

        if (selected.empty()) {
            if (required)
                fail("no functions matched in %s", path.c_str());
            log_verbose("skipping %s: no matching functions", path.c_str());
            return false;
        }

        if (options_.show_args)
            annotate_parameters(path, selected);

        const size_t base = names_.size();
        for (size_t i = 0; i < selected.size(); ++i) {
            selected[i].function_id = base + i;
            names_.push_back(selected[i].name);
            signatures_.push_back(std::move(selected[i].signature));

            FunctionMetadata metadata;
            metadata.name = selected[i].name;
            metadata.linkage_name = selected[i].linkage_name;
            metadata.module_path = selected[i].module_path;
            metadata.module_build_id = selected[i].module_build_id.empty()
                                           ? module.build_id
                                           : selected[i].module_build_id;
            metadata.source_file = selected[i].source_file;
            metadata.source_line = selected[i].source_line;
            metadata.file_offset = selected[i].file_offset;
            functions_.push_back(std::move(metadata));
        }

        if (probes_)
            probes_->attach(path, selected, ret_mode_);

        log_info("resolved %zu function(s) in %s%s%s", selected.size(),
                 path.c_str(), module.build_id.empty() ? "" : ", build-id ",
                 module.build_id.c_str());

        if (!warned_exceptions_ && options_.return_mode == "uretprobe" &&
            module.has_exception_tables) {
            warned_exceptions_ = true;
            log_warn("target contains C++ exception handling; uretprobes can "
                     "terminate the process when an exception unwinds through a "
                     "traced function. Use --return-mode=ret to avoid this.");
        }

        if (!warned_go_ && module.is_go_binary) {
            warned_go_ = true;
            if (options_.return_mode == "uretprobe") {
                log_warn("target looks like a Go binary; uretprobes can crash "
                         "the Go runtime during stack growth or GC. Use "
                         "--return-mode=ret.");
            } else {
                log_warn("target looks like a Go binary; goroutine stack "
                         "switches and growth make nesting unreliable, so "
                         "depths and spans may be wrong.");
            }
        }

        modules_.push_back({path, std::move(selected)});
        return true;
    }

    const std::vector<std::string>& names() const { return names_; }
    const std::vector<FunctionSignature>& signatures() const
    {
        return signatures_;
    }
    const std::vector<FunctionMetadata>& functions() const
    {
        return functions_;
    }
    const std::vector<PlannedModule>& modules() const { return modules_; }
    bool has_path(const std::string& path) const
    {
        return attached_.count(path) != 0;
    }

private:
    const Options& options_;
    FunctionFilter& filter_;
    ProbeManager* probes_;
    bool ret_mode_;

    std::vector<std::string> names_;
    std::vector<FunctionSignature> signatures_;
    std::vector<FunctionMetadata> functions_;
    std::vector<PlannedModule> modules_;
    std::unordered_set<std::string> attached_;
    bool warned_exceptions_ = false;
    bool warned_go_ = false;
};

class ChildGuard {
public:
    ChildGuard() = default;
    ~ChildGuard() { kill_now(); }

    void arm(pid_t pid) { pid_ = pid; }
    void release() { pid_ = -1; }

    void kill_now()
    {
        if (pid_ > 0) {
            kill(pid_, SIGKILL);
            waitpid(pid_, nullptr, 0);
            pid_ = -1;
        }
    }

private:
    pid_t pid_ = -1;
};

void print_version()
{
    printf("callgraph %s\n", CALLGRAPH_VERSION);
    printf("libbpf %d.%d\n", LIBBPF_MAJOR_VERSION, LIBBPF_MINOR_VERSION);
    printf("otlp protobuf: %s\n", otlp_protobuf_available() ? "yes" : "no");
    printf("otlp http: %s\n", otlp_http_available() ? "yes" : "no");

    struct utsname uts;
    if (uname(&uts) == 0)
        printf("kernel %s\n", uts.release);
}

}  // namespace

int main(int argc, char** argv)
{
    try {
        if (argc >= 2 && std::string(argv[1]) == "export") {
            const ExportOptions export_options = parse_export_args(argc, argv);
            return run_export(export_options);
        }

        const Options options = parse_args(argc, argv);
        if (options.help) {
            usage(stdout);
            return 0;
        }
        if (options.version) {
            print_version();
            return 0;
        }
        if (options.verbose)
            g_log_level = LogLevel::Verbose;

        struct sigaction action = {};
        action.sa_handler = [](int) { g_stop = 1; };
        sigemptyset(&action.sa_mask);
        sigaction(SIGINT, &action, nullptr);
        sigaction(SIGTERM, &action, nullptr);
        signal(SIGPIPE, SIG_IGN);

        pid_t target = -1;
        bool is_child = false;
        std::string exe;

        ChildGuard child_guard;

        if (options.command == "run") {
            std::vector<char*> child_argv;
            child_argv.reserve(options.program.size() + 1);
            for (const auto& arg : options.program)
                child_argv.push_back(const_cast<char*>(arg.c_str()));
            child_argv.push_back(nullptr);

            target = ProcessController::launch(child_argv.data());
            is_child = true;
            child_guard.arm(target);
            exe = ProcessController::exe_path(target);
        } else {
            target = options.pid;
            exe = ProcessController::exe_path(target);
        }

        FunctionFilter filter(options.include, options.exclude, options.use_regex);

        std::vector<std::string> initial_paths;
        initial_paths.push_back(exe);
        if (options.all_modules || !options.modules.empty()) {
            if (options.all_modules)
                log_warn("tracing all mapped modules; this can install many probes");
            for (const auto& loaded : ModuleManager(target).scan()) {
                if (loaded.path == exe)
                    continue;
                if (!options.all_modules &&
                    !module_matches(loaded.path, options.modules))
                    continue;
                initial_paths.push_back(loaded.path);
            }
        }

        const bool multi_module = options.all_modules || !options.modules.empty();

        if (options.dry_run) {
            ModuleRegistry registry(options, filter, nullptr, false);
            registry.add(exe, !multi_module);
            for (size_t i = 1; i < initial_paths.size(); ++i)
                registry.add(initial_paths[i], false);

            if (registry.modules().empty())
                fail("no functions matched in the selected module(s)");

            for (const auto& module : registry.modules()) {
                for (const auto& function : module.functions) {
                    printf("%6" PRIu64 "  0x%08" PRIx64 "  %s\n",
                           function.function_id, function.file_offset,
                           function.name.c_str());
                }
            }
            if (is_child)
                child_guard.kill_now();
            return 0;
        }

        ClockConverter clock_converter;
        Output output(options.output, options.wall_clock
                                          ? TimestampMode::WallClock
                                          : TimestampMode::BootSeconds,
                      options.indent_step, &clock_converter);
        ProbeManager probes(target, options.ringbuf_size, options.probe_batch_size,
                            options.verbose);
        probes.load();
        probes.set_capture_arguments(options.show_args);

        const bool ret_mode = options.return_mode == "ret";
        ModuleRegistry registry(options, filter, &probes, ret_mode);
        registry.add(exe, !multi_module);
        for (size_t i = 1; i < initial_paths.size(); ++i)
            registry.add(initial_paths[i], false);

        uint64_t seed_hi = 0;
        uint64_t seed_lo = 0;
        random_seed(&seed_hi, &seed_lo);
        const std::string service_instance_id =
            session_id_hex(seed_hi, seed_lo);

        std::string service_name = options.service_name;
        if (service_name.empty()) {
            if (const char* environment = getenv("OTEL_SERVICE_NAME"))
                service_name = environment;
        }
        if (service_name.empty())
            service_name = executable_basename(exe);

        TraceScope trace_scope = TraceScope::Root;
        parse_trace_scope(options.trace_scope, &trace_scope);

        const std::string exporter_mode =
            options.exporter_set ? options.exporter : "stdout";
        const bool network_export =
            exporter_mode == "otlp" || exporter_mode == "otlp-http";
        const bool file_export = exporter_mode == "otlp-json";

        std::string otel_endpoint;
        OtlpProtocol otel_protocol = OtlpProtocol::JsonHttp;
        if (exporter_mode == "otlp") {
            otel_endpoint = options.endpoint.empty() ? "localhost:4317"
                                                     : options.endpoint;
            otel_protocol = OtlpProtocol::Grpc;
        } else if (exporter_mode == "otlp-http") {
            otel_endpoint = options.endpoint.empty() ? "http://localhost:4318"
                                                     : options.endpoint;
            if (!is_http_url(otel_endpoint))
                otel_endpoint = "http://" + otel_endpoint;
            otel_endpoint = normalize_otel_endpoint(otel_endpoint);
            otel_protocol = OtlpProtocol::ProtobufHttp;
        }

        std::unique_ptr<OtelExporter> exporter;
        std::unique_ptr<SpanGenerator> span_generator;
        if (network_export || file_export) {
            OtelConfig otel_config;
            otel_config.output_path = file_export ? options.export_file : "";
            otel_config.endpoint = otel_endpoint;
            otel_config.protocol = otel_protocol;
            otel_config.headers = options.headers;
            otel_config.service_name = service_name;
            otel_config.service_namespace = options.service_namespace;
            otel_config.service_instance_id = service_instance_id;
            otel_config.executable_name = executable_basename(exe);
            otel_config.executable_path = exe;
            otel_config.command_line =
                options.command == "run" ? join_program(options.program)
                                         : read_command_line(target);
            otel_config.pid = target;
            otel_config.return_mode = options.return_mode;
            otel_config.trace_scope = trace_scope_name(trace_scope);
            otel_config.attach_mode = options.command == "attach";
            otel_config.monotonic_offset_ns =
                static_cast<uint64_t>(clock_converter.offset_ns());
            otel_config.batch_spans = options.batch_size;
            otel_config.batch_bytes = options.batch_bytes;
            otel_config.queue_spans = options.queue_spans;
            otel_config.flush_ms = options.flush_interval_ms;
            otel_config.timeout_ms = options.timeout_ms;
            otel_config.gzip = options.compression == "gzip";
            fill_host_otel_config(otel_config);

            exporter = std::make_unique<OtelExporter>(otel_config);

            SpanGeneratorConfig builder_config;
            builder_config.scope = trace_scope;
            builder_config.seed_hi = seed_hi;
            builder_config.seed_lo = seed_lo;
            builder_config.timestamps_are_unix = false;
            builder_config.clock = &clock_converter;
            builder_config.functions = &registry.functions();
            builder_config.sample_rate = options.sample_rate;
            builder_config.pid = target;
            builder_config.read_thread_names = true;
            span_generator = std::make_unique<SpanGenerator>(
                builder_config, [&exporter](SpanRecord&& span) {
                    (*exporter).export_span(std::move(span));
                });
        }

        if (registry.names().empty())
            log_info("no functions matched yet; waiting for matching modules to load");

        CallStack stack(registry.names(),
                        options.show_args ? &registry.signatures() : nullptr,
                        output, options.max_depth, options.verbose,
                        options.histogram, span_generator.get());

        if (is_child) {
            ProcessController::detach(target);
            child_guard.release();
        }

        auto refresh_modules = [&]() {
            if (!options.all_modules && options.modules.empty())
                return;
            try {
                for (const auto& loaded : ModuleManager(target).scan()) {
                    if (registry.has_path(loaded.path))
                        continue;
                    if (!options.all_modules &&
                        !module_matches(loaded.path, options.modules))
                        continue;
                    registry.add(loaded.path, false);
                }
            } catch (const std::exception&) {
                // The target may be exiting; the main loop will notice.
            }
        };

        uint64_t last_calibration_ns = ClockConverter::now_monotonic_ns();
        auto collector_tick = [&]() {
            refresh_modules();
            const uint64_t now = ClockConverter::now_monotonic_ns();
            if (now - last_calibration_ns >= 30000000000ULL) {
                clock_converter.recalibrate();
                last_calibration_ns = now;
            }
        };

        EventCollector collector(probes.events_fd(), stack);
        collector.run(target, is_child ? target : -1, collector_tick);

        std::string report;
        if (options.histogram) {
            stack.finish_statistics();
            report = format_histogram_report(stack.stats(), registry.names());
        }

        if (span_generator)
            stack.finish_spans(ClockConverter::now_monotonic_ns());

        if (!options.trace_metadata.empty()) {
            TraceMetadata metadata;
            metadata.service_name = service_name;
            metadata.service_namespace = options.service_namespace;
            metadata.service_instance_id = service_instance_id;
            metadata.pid = target;
            metadata.monotonic_offset_ns =
                static_cast<uint64_t>(clock_converter.offset_ns());
            metadata.seed_hi = seed_hi;
            metadata.seed_lo = seed_lo;
            metadata.return_mode = options.return_mode;
            metadata.trace_scope = trace_scope_name(trace_scope);
            metadata.attach_mode = options.command == "attach";
            metadata.functions = registry.functions();
            write_trace_metadata(options.trace_metadata, metadata);
        }

        output.finish(report);

        if (exporter) {
            exporter->finish();
            fprintf(stderr,
                    "callgraph: OTLP %" PRIu64 " span(s) exported, "
                    "%" PRIu64 " dropped, %" PRIu64 " failed\n",
                    exporter->exported(), exporter->dropped(),
                    exporter->failed());
        }
        if (span_generator && span_generator->spans_sampled_out() != 0) {
            fprintf(stderr, "callgraph: sampled out %" PRIu64 " span(s)\n",
                    span_generator->spans_sampled_out());
        }

        const uint64_t lost = probes.lost_events();
        const uint64_t events = stack.entries() + stack.returns();

        fprintf(stderr,
                "callgraph: %" PRIu64 " events, %" PRIu64 " entries, "
                "%" PRIu64 " returns, %" PRIu64 " lost, %" PRIu64
                " desync, %" PRIu64 " stray, %" PRIu64 " dropped\n",
                events, stack.entries(), stack.returns(), lost, stack.desyncs(),
                stack.stray_returns(), output.dropped());

        if (lost != 0)
            log_warn("ring buffer overflowed: the trace is incomplete");
        if (probes.attach_failures() != 0)
            log_warn("%" PRIu64 " probe(s) failed to attach",
                     probes.attach_failures());

        if (exporter && options.fail_on_export_error && exporter->failed() != 0)
            return 1;
        return 0;
    } catch (const std::exception& error) {
        fprintf(stderr, "callgraph: %s\n", error.what());
        return 1;
    }
}
