#include "cli_internal.h"

#include <sys/utsname.h>
#include <unistd.h>

#include <bpf/libbpf_version.h>

#include <algorithm>
#include <cerrno>
#include <cinttypes>
#include <cmath>
#include <cstdarg>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <initializer_list>
#include <iterator>
#include <string>
#include <vector>

#include "callgraph/clock_converter.h"
#include "callgraph/otel_exporter.h"
#include "callgraph/otlp_proto.h"
#include "callgraph/span_generator.h"

namespace callgraph {
namespace {

ProgramMode g_mode = ProgramMode::Run;

// Help options use up to three levels: a master option, the options that
// refine or require it, and values nested under those options.
struct HelpOption {
    const char* flags;
    const char* desc;
    int level = 0;
};

constexpr int kPrimaryShortIndent = 2;
constexpr int kPrimaryIndent = 6;
constexpr int kSecondaryIndent = 10;
constexpr int kTertiaryIndent = 14;
constexpr int kDescColumn = 32;

void print_help_description(FILE* out, const char* desc, int column)
{
    const char* line = desc;
    while (true) {
        const char* newline = std::strchr(line, '\n');
        const int length = newline ? static_cast<int>(newline - line)
                                   : static_cast<int>(std::strlen(line));
        fprintf(out, "%*s%.*s\n", column, "", length, line);
        if (!newline)
            break;
        line = newline + 1;
    }
}

void print_help_option(FILE* out, const HelpOption& option)
{
    const bool short_option =
        option.flags[0] == '-' && option.flags[1] != '-';
    const int indent =
        option.level == 0
            ? (short_option ? kPrimaryShortIndent : kPrimaryIndent)
            : option.level == 1 ? kSecondaryIndent : kTertiaryIndent;
    const int width = kDescColumn - indent;
    const int flags_length = static_cast<int>(std::strlen(option.flags));

    if (flags_length >= width) {
        // Flags too long for the column put their description on the next
        // line, still at the shared description column.
        fprintf(out, "%*s%s\n", indent, "", option.flags);
        print_help_description(out, option.desc, kDescColumn);
        return;
    }

    const char* newline = std::strchr(option.desc, '\n');
    const int first_length =
        newline ? static_cast<int>(newline - option.desc)
                : static_cast<int>(std::strlen(option.desc));
    fprintf(out, "%*s%-*s%.*s\n", indent, "", width, option.flags,
            first_length, option.desc);
    if (newline)
        print_help_description(out, newline + 1, kDescColumn);
}

void print_help_options(FILE* out, std::initializer_list<HelpOption> options)
{
    for (const HelpOption& option : options)
        print_help_option(out, option);
}

void print_help_section(FILE* out, const char* title,
                        std::initializer_list<HelpOption> options)
{
    fprintf(out, "%s:\n", title);
    print_help_options(out, options);
    fputc('\n', out);
}

void print_tracing_options(FILE* out)
{
    print_help_section(out, "Tracing options", {
        {"-o, --output <file>", "write events to <file> (default: stdout)"},
        {"--root-scope <glob>",
         "functions that may start a traced call tree (repeatable)"},
        {"--exclude <glob>", "skip functions matching <glob> (repeatable)"},
        {"--regex", "treat --root-scope/--exclude as extended regex"},
        {"--return-mode <mode>", "uretprobe (default) or ret (exception-safe)"},
        {"--no-rsp-resync",
         "keep frames across stack switches (stackful\n"
         "runtimes such as ucontext, Boost.Context);\n"
         "disables longjmp/siglongjmp depth repair"},
        {"--all-modules", "trace every mapped ELF module"},
        {"--module <glob>", "also trace mapped modules matching <glob>"},
        {"--static-graph <file>",
         "call-graph facts from callgraph-disasm (repeatable);\n"
         "used by --trace-depth and required by --return-mode=ret.\n"
         "The callgraph wrapper runs callgraph-disasm and passes\n"
         "generated JSON facts automatically; with the wrapper,\n"
         "pass this only to reuse existing facts"},
        {"-T, --wall-clock",
         "wall-clock timestamps (default: seconds since boot)"},
        {"--max-depth <n>", "print events with depth <= <n> (default: unlimited)"},
        {"--trace-depth <n>",
         "trace user frames <n> levels below the root\n"
         "(0: root only; default: unlimited);\n"
         "<n> > 0 prunes probes along direct calls;\n"
         "kernel events unaffected"},
        {"--indent <n>", "indent names by depth*<n> spaces (default: 0)"},
        {"--show-args",
         "show function arguments after names (needs DWARF)"},
        {"--histogram",
         "append per-root call trees and latency histograms to the output"},
        {"--ingest-sample-rate <rate>",
         "ingest root traces at rate <rate>, 0..1 (default: 1)"},
        {"--log-rate-limit <n>",
         "limit stdout user and kernel event lines to <n> per second each\n"
         "(default: 0, off)"},
        {"--probe-batch-size <n>",
         "functions per uprobe_multi link (default: 1000)"},
        {"--ringbuf-size <size>",
         "function and kernel ring buffer size, k/m/g suffix (default: 16m)"},
        {"--dry-run", "list resolved functions and exit"},
        {"--trace-metadata <file>", "write an offline-conversion sidecar"},
    });
}

void print_kernel_options(FILE* out)
{
    print_help_section(out, "Kernel event options (--kernel)", {
        {"--kernel", "enable correlated kernel event tracing"},
        {"--sched", "trace scheduler switch/wakeup events", 1},
        {"--futex", "trace futex syscall begin/end events", 1},
        {"--io", "trace read/write/fsync syscall events", 1},
        {"--block", "trace block request events (global)", 1},
        {"--network", "trace socket syscalls and TCP retransmits", 1},
        {"--memory", "trace page faults and direct reclaim", 1},
        {"--events <events>", "comma-separated: sched,futex,io,block,net,mm", 1},
        {"--preset <preset>",
         "latency (default), proxy, storage, computation, full, or extended", 1},
        {"latency", "sched, futex, io, net syscalls", 2},
        {"proxy", "sched, futex, io, net syscalls, TCP retransmits", 2},
        {"storage", "sched, futex, io, direct reclaim", 2},
        {"computation", "sched, futex, direct reclaim, page faults", 2},
        {"full",
         "sched, futex, io, net syscalls, direct reclaim,\n"
         "page faults, TCP retransmits",
         2},
        {"extended",
         "sched, futex, io, block, net syscalls, direct reclaim,\n"
         "page faults, TCP retransmits",
         2},
        {"--merge-window <duration>",
         "reorder window, ns/us/ms/s (default: 1ms)", 1},
        {"--require-events",
         "fail if a requested tracepoint is unavailable", 1},
    });
}

void print_live_export_options(FILE* out)
{
    print_help_section(out, "Live export options (--exporter)", {
        {"--exporter <mode>", "stdout (default), otlp, otlp-http, or otlp-json"},
        {"--endpoint <url>",
         "OTLP endpoint; default localhost:4317 / :4318", 1},
        {"--export-file <file>", "output file for --exporter otlp-json", 1},
        {"--service-name <name>",
         "override service.name (default: exe basename)", 1},
        {"--service-namespace <name>", "override service.namespace", 1},
        {"--trace-scope <mode>", "root (default), thread, or process", 1},
        {"--batch-size <n>", "spans per OTLP batch (default: 512)", 1},
        {"--batch-bytes <n>", "OTLP request size limit (default: 1m)", 1},
        {"--flush-interval <n>",
         "OTLP batch flush interval in ms (default: 1000)", 1},
        {"--timeout-ms <n>", "OTLP HTTP timeout (default: 5000)", 1},
        {"--queue-spans <n>", "exporter queue limit (default: 10000)", 1},
        {"--header <key=value>", "add an HTTP header (repeatable)", 1},
        {"--compression <mode>", "none (default) or gzip (OTLP/HTTP only)", 1},
        {"--sample-rate <rate>",
         "baseline root-trace sampling rate, 0..1 (default: 1)", 1},
        {"--fail-on-export-error", "exit non-zero if export fails", 1},
        {"--complete-traces", "export only complete traces", 1},
        {"--trace-buffer-bytes <size>",
         "trace buffer byte limit (default: 256m)", 2},
        {"--trace-buffer-spans <n>",
         "trace buffer span limit (default: 1000000)", 2},
        {"--outlier-latency-quantile <quantile>",
         "export traces above the trace-duration <quantile>\n"
         "quantile; annotates root spans with\n"
         "callgraph.quantile (root scope)",
         2},
    });
}

void print_export_input_options(FILE* out)
{
    print_help_options(out, {
        {"--input <file>", "callgraph text trace to convert (--otel/--flame)"},
    });
}

void print_export_output_option(FILE* out)
{
    print_help_options(out, {
        {"-o, --output <file>",
         "write the converted output to <file> (default: stdout)"},
    });
}

void print_otel_option_group(FILE* out)
{
    print_help_options(out, {
        {"--otel", "convert a text trace to OpenTelemetry OTLP/JSON spans"},
        {"--endpoint <url>",
         "POST the OTLP/JSON body to <url>\n"
         "(OTLP/HTTP JSON; path defaults to /v1/traces)", 1},
        {"--service-name <name>", "override service.name", 1},
        {"--service-namespace <name>", "override service.namespace", 1},
        {"--metadata <file>", "trace metadata sidecar", 1},
        {"--assume-local-capture",
         "assume the trace came from this host/boot session", 1},
        {"--trace-scope <mode>", "root (default), thread, or process", 1},
        {"--trace-id-seed <hex>", "deterministic trace IDs", 1},
        {"--sample-rate <rate>",
         "baseline root-trace sampling rate, 0..1", 1},
        {"--complete-traces", "export only complete traces", 1},
        {"--trace-buffer-bytes <size>",
         "trace buffer byte limit (default: 256m)", 2},
        {"--trace-buffer-spans <n>",
         "trace buffer span limit (default: 1000000)", 2},
        {"--outlier-latency-quantile <quantile>",
         "export traces above the trace-duration <quantile>\n"
         "quantile; annotates root spans with\n"
         "callgraph.quantile (root scope)",
         2},
        {"--batch-size <n>", "spans per OTLP batch (default: 512)", 1},
        {"--batch-bytes <n>", "request size limit (default: 1m)", 1},
        {"--flush-interval <n>",
         "batch flush interval in ms (default: 1000)", 1},
        {"--timeout-ms <n>", "HTTP timeout (default: 5000)", 1},
        {"--queue-spans <n>", "exporter queue limit (default: 10000)", 1},
        {"--header <key=value>", "add an HTTP header (repeatable)", 1},
        {"--compression <mode>", "none (default) or gzip", 1},
        {"--fail-on-export-error", "exit non-zero if export fails", 1},
    });
}

void print_static_option_group(FILE* out)
{
    print_help_options(out, {
        {"--static", "render a direct-call graph from facts"},
        {"--static-graph <file>",
         "facts produced by callgraph-disasm (repeatable);\n"
         "required when callgraph-export --static is run directly.\n"
         "The callgraph wrapper runs callgraph-disasm on <module>\n"
         "and passes generated JSON facts automatically; with the\n"
         "wrapper, pass this only to reuse existing facts", 1},
        {"--root-scope <glob>",
         "with --static, functions that start a tree (repeatable)", 1},
        {"--regex",
         "with --static, treat --root-scope as extended regex", 1},
    });
}

void print_flame_option_group(FILE* out)
{
    print_help_options(out, {
        {"--flame", "convert a text trace to folded stacks for flame graphs"},
    });
}

void print_otel_notes(FILE* out)
{
    fprintf(out,
            "\n"
            "  --output and --endpoint are alternatives; --otel requires one.\n"
            "  --otel emits OTLP/JSON only; for live OTLP/gRPC or OTLP/HTTP\n"
            "  protobuf use --exporter otlp or --exporter otlp-http.\n");
}

void print_static_notes(FILE* out)
{
    fprintf(out,
            "\n"
            "  --static renders facts written by callgraph-disasm.  The\n"
            "  callgraph wrapper generates them automatically from <module>;\n"
            "  pass --static-graph <file> only to reuse existing facts.\n"
            "  callgraph-export never links a disassembler.\n");
}

void print_offline_export_options(FILE* out)
{
    fprintf(out,
            "Offline export options:\n"
            "  Convert an existing text trace.  --otel emits an OTLP/JSON\n"
            "  request body; --flame emits folded stacks; --static renders a\n"
            "  direct-call graph from callgraph-disasm facts.\n");
    print_export_input_options(out);
    print_otel_option_group(out);
    print_static_option_group(out);
    print_flame_option_group(out);
    print_export_output_option(out);
    fprintf(out,
            "\n"
            "  --output and --endpoint are alternatives; --otel requires one.\n"
            "  --otel emits OTLP/JSON only; for live OTLP/gRPC or OTLP/HTTP\n"
            "  protobuf use --exporter otlp or --exporter otlp-http.\n"
            "  --static renders facts written by callgraph-disasm.  The\n"
            "  callgraph wrapper generates them automatically from <module>;\n"
            "  pass --static-graph <file> only to reuse existing facts.\n"
            "  callgraph-export never links a disassembler.\n"
            "\n");
}

void print_general_options(FILE* out)
{
    print_help_section(out, "General options", {
        {"-v, --verbose", "verbose diagnostics"},
        {"-h, --help", "show this help"},
        {"--version", "show version"},
    });
}

void print_live_examples(FILE* out, bool attach)
{
    fprintf(out,
            "Examples:\n");
    if (!attach) {
        fprintf(out,
                "  Trace a program:\n"
                "    sudo callgraph run -- ./demo\n"
                "    sudo callgraph run --root-scope 'Database::*' -- ./demo\n"
                "    callgraph run --dry-run -- ./demo\n"
                "\n");
    } else {
        fprintf(out,
                "  Attach to a running process:\n"
                "    sudo callgraph attach -p 12345\n"
                "    sudo callgraph attach -p 12345 --root-scope 'Database::*'\n"
                "\n");
    }
    fprintf(out,
            "  Correlated kernel events:\n");
    if (!attach) {
        fprintf(out,
                "    sudo callgraph run --kernel --preset latency -- ./demo\n"
                "    sudo callgraph run --kernel --preset proxy -- ./proxy\n"
                "    sudo callgraph run --kernel --preset storage -- ./db\n"
                "    sudo callgraph run --kernel --sched --futex -- ./demo\n"
                "    sudo callgraph run --kernel --memory --network -- ./demo\n");
    } else {
        fprintf(out,
                "    sudo callgraph attach -p 12345 --kernel\n"
                "    sudo callgraph attach -p 12345 --kernel --block --io --network\n");
    }
    fprintf(out,
            "\n"
            "  Live export:\n");
    if (!attach) {
        fprintf(out,
                "    sudo callgraph run --exporter otlp --endpoint localhost:4317 -- ./demo\n"
                "    sudo callgraph run --exporter otlp-http -- ./demo\n"
                "    sudo callgraph run --exporter otlp-json --export-file trace.json -- ./demo\n");
    } else {
        fprintf(out,
                "    sudo callgraph attach -p 12345 --exporter otlp \\\n"
                "        --endpoint localhost:4317 --service-name my_app\n");
    }
    fprintf(out,
            "\n"
            "  Offline conversion: run 'callgraph export --help'\n");
}

void print_export_otel_examples(FILE* out)
{
    fprintf(out,
            "Examples:\n"
            "  # ISO wall-clock trace\n"
            "  callgraph export --otel --input trace.log --output spans.json\n"
            "\n"
            "  # Record the timestamp anchor while capturing, then convert\n"
            "  callgraph export --otel --input trace.log \\\n"
            "      --metadata trace.meta --output spans.json\n"
            "\n"
            "  # Boot-second trace with no sidecar\n"
            "  callgraph export --otel --input trace.log --output spans.json \\\n"
            "      --assume-local-capture\n");
}

void print_export_flame_examples(FILE* out)
{
    fprintf(out,
            "Examples:\n"
            "  callgraph export --flame --input trace.log --output stacks.folded\n"
            "  flamegraph.pl stacks.folded > flame.svg\n");
}

void print_export_static_examples(FILE* out)
{
    fprintf(out,
            "Examples:\n"
            "  callgraph disasm ./app -o facts.json\n"
            "  callgraph export --static --static-graph facts.json\n"
            "  callgraph disasm --all-modules ./app -o facts.json\n"
            "  callgraph export --static --static-graph facts.json \\\n"
            "      --regex --root-scope '^main$'\n");
}

void print_export_examples(FILE* out)
{
    fprintf(out,
            "Examples:\n"
            "  # Record the timestamp anchor while capturing, then convert\n"
            "  callgraph run -o trace.log --trace-metadata trace.meta -- ./app\n"
            "  callgraph export --otel --input trace.log \\\n"
            "      --metadata trace.meta --output spans.json\n"
            "\n"
            "  # ISO wall-clock trace with no sidecar\n"
            "  callgraph export --otel --input trace.log --output spans.json\n"
            "\n"
            "  # Boot-second trace with no sidecar; approximate this-host anchor\n"
            "  callgraph export --otel --input trace.log --output spans.json \\\n"
            "      --assume-local-capture\n"
            "\n"
            "  # Folded stacks for flamegraph.pl / inferno-flamegraph\n"
            "  callgraph export --flame --input trace.log --output stacks.folded\n"
            "  flamegraph.pl stacks.folded > flame.svg\n"
            "\n"
            "  # Static call graph from disassembler facts\n"
            "  callgraph disasm ./app -o facts.json\n"
            "  callgraph export --static --static-graph facts.json\n"
            "  callgraph disasm --all-modules ./app -o facts.json\n"
            "  callgraph export --static --static-graph facts.json \\\n"
            "      --regex --root-scope '^main$'\n");
}

}  // namespace

void set_program_mode(const char* argv0, ProgramMode mode)
{
    g_mode = mode;
    std::string name =
        argv0 ? std::filesystem::path(argv0).filename().string() : "";
    if (name.empty()) {
        name = mode == ProgramMode::Run        ? "callgraph-run"
               : mode == ProgramMode::Attach   ? "callgraph-attach"
                                               : "callgraph-export";
    }
    set_program_name(name.c_str());
}

ProgramMode program_mode()
{
    return g_mode;
}

void usage_export(FILE* out, ExportMode mode, bool mode_set)
{
    if (!mode_set) {
        fprintf(out,
                "usage:\n"
                "  callgraph-export --otel|--flame --input <trace> [<options>]\n"
                "  callgraph-export --static --static-graph <file> [<options>]\n"
                "\n");
        print_offline_export_options(out);
        print_general_options(out);
        print_export_examples(out);
        return;
    }

    switch (mode) {
    case ExportMode::Otel:
        fprintf(out,
                "usage:\n"
                "  callgraph-export --otel --input <trace> [<options>]\n"
                "\n");
        fprintf(out, "OTel export options (--otel):\n");
        print_export_input_options(out);
        print_otel_option_group(out);
        print_export_output_option(out);
        print_otel_notes(out);
        print_general_options(out);
        print_export_otel_examples(out);
        break;
    case ExportMode::Flame:
        fprintf(out,
                "usage:\n"
                "  callgraph-export --flame --input <trace> [<options>]\n"
                "\n");
        fprintf(out, "Flame export options (--flame):\n");
        print_export_input_options(out);
        print_flame_option_group(out);
        print_export_output_option(out);
        print_general_options(out);
        print_export_flame_examples(out);
        break;
    case ExportMode::Static:
        fprintf(out,
                "usage:\n"
                "  callgraph-export --static --static-graph <file> [<options>]\n"
                "\n");
        fprintf(out, "Static export options (--static):\n");
        print_static_option_group(out);
        print_export_output_option(out);
        print_static_notes(out);
        print_general_options(out);
        print_export_static_examples(out);
        break;
    }
}

void usage(FILE* out)
{
    switch (g_mode) {
    case ProgramMode::Run:
        fprintf(out,
                "usage:\n"
                "  callgraph-run [<options>] -- <program> [<args>...]\n"
                "\n");
        print_tracing_options(out);
        print_kernel_options(out);
        print_live_export_options(out);
        print_general_options(out);
        print_live_examples(out, false);
        break;
    case ProgramMode::Attach:
        fprintf(out,
                "usage:\n"
                "  callgraph-attach [<options>] -p <pid>\n"
                "\n");
        print_tracing_options(out);
        print_kernel_options(out);
        print_live_export_options(out);
        print_general_options(out);
        print_live_examples(out, true);
        break;
    case ProgramMode::Export:
        usage_export(out, ExportMode::Otel, false);
        break;
    }
}

void usage_brief(FILE* out)
{
    switch (g_mode) {
    case ProgramMode::Run:
        fprintf(out,
                "usage:\n"
                "  callgraph-run [<options>] -- <program> [<args>...]\n"
                "\n"
                "Run 'callgraph-run --help' for all options.\n");
        break;
    case ProgramMode::Attach:
        fprintf(out,
                "usage:\n"
                "  callgraph-attach [<options>] -p <pid>\n"
                "\n"
                "Run 'callgraph-attach --help' for all options.\n");
        break;
    case ProgramMode::Export:
        fprintf(out,
                "usage:\n"
                "  callgraph-export --otel|--flame --input <trace> [<options>]\n"
                "  callgraph-export --static --static-graph <file> [<options>]\n"
                "\n"
                "Run 'callgraph-export --help' for all options.\n");
        break;
    }
}

[[noreturn]] void usage_error(const char* fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    fprintf(stderr, "%s: ", program_name());
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n\n");
    va_end(ap);
    usage_brief(stderr);
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

double parse_fraction(const std::string& text, const std::string& option)
{
    char* end = nullptr;
    errno = 0;
    const double value = strtod(text.c_str(), &end);
    if (errno != 0 || end == text.c_str() || *end != '\0' ||
        !std::isfinite(value) || value < 0.0 || value > 1.0) {
        usage_error("%s must be between 0 and 1", option.c_str());
    }
    return value;
}

double parse_quantile(const std::string& text, const std::string& option)
{
    char* end = nullptr;
    errno = 0;
    const double value = strtod(text.c_str(), &end);
    if (errno != 0 || end == text.c_str() || *end != '\0' ||
        !std::isfinite(value) || value <= 0.0 || value >= 1.0) {
        usage_error("%s must be between 0 and 1 (exclusive)", option.c_str());
    }
    return value;
}

uint64_t parse_duration_ns(const std::string& text, const std::string& option)
{
    char* end = nullptr;
    errno = 0;
    unsigned long long value = strtoull(text.c_str(), &end, 0);
    if (errno != 0 || end == text.c_str())
        usage_error("invalid value for %s: '%s'", option.c_str(), text.c_str());

    if (strncmp(end, "ns", 2) == 0) {
        end += 2;
    } else if (strncmp(end, "us", 2) == 0) {
        value *= 1000ULL;
        end += 2;
    } else if (strncmp(end, "ms", 2) == 0) {
        value *= 1000000ULL;
        end += 2;
    } else if (*end == 's') {
        value *= 1000000000ULL;
        ++end;
    }

    if (*end != '\0')
        usage_error("invalid value for %s: '%s'", option.c_str(), text.c_str());
    return static_cast<uint64_t>(value);
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

void print_otel_drop_stats(const OtelExporter& exporter)
{
    const OtelDropStats stats = exporter.drop_stats();
    if (stats.total() == 0)
        return;

    std::string reasons;
    for (size_t i = 0; i < kOtelDropReasonCount; ++i) {
        if (stats.counts[i] == 0)
            continue;
        if (!reasons.empty())
            reasons.push_back(' ');
        reasons += otel_drop_reason_name(static_cast<OtelDropReason>(i));
        reasons.push_back('=');
        reasons += std::to_string(stats.counts[i]);
    }
    fprintf(stderr, "callgraph: OTLP drop reasons: %s\n", reasons.c_str());
}

void print_trace_buffer_stats(const SpanGenerator& generator)
{
    fprintf(stderr,
            "callgraph: trace buffer: %" PRIu64 " completed, %" PRIu64
            " exported, %zu active, %" PRIu64 " overflowed, %" PRIu64
            " orphaned\n",
            generator.traces_completed(), generator.traces_flushed(),
            generator.active_trace_buffers(), generator.traces_overflowed(),
            generator.traces_orphaned());
    if (generator.spans_trace_buffer_dropped() != 0) {
        fprintf(stderr,
                "callgraph: trace buffer dropped %" PRIu64 " span(s)\n",
                generator.spans_trace_buffer_dropped());
    }
}

void print_outlier_stats(const SpanGenerator& generator)
{
    if (!generator.outlier_enabled())
        return;
    fprintf(stderr,
            "callgraph: outlier sampling: %" PRIu64 " trace(s) seen, "
            "%" PRIu64 " trace(s) reported, %" PRIu64
            " span(s) reported, ",
            generator.outlier_traces_seen(),
            generator.traces_outlier_reported(),
            generator.spans_outlier_reported());
    if (generator.outlier_threshold_ns() == UINT64_MAX)
        fprintf(stderr, "threshold pending\n");
    else
        fprintf(stderr, "threshold %" PRIu64 " ns\n",
                generator.outlier_threshold_ns());
}

void print_kernel_span_stats(const SpanGenerator& generator)
{
    if (generator.kernel_spans_closed() == 0 &&
        generator.kernel_spans_point() == 0 &&
        generator.kernel_spans_unparented() == 0 &&
        generator.kernel_spans_sampled_out() == 0) {
        return;
    }
    fprintf(stderr,
            "callgraph: kernel spans: %" PRIu64 " interval, %" PRIu64
            " point, %" PRIu64 " unparented, %" PRIu64 " sampled out\n",
            generator.kernel_spans_closed(), generator.kernel_spans_point(),
            generator.kernel_spans_unparented(),
            generator.kernel_spans_sampled_out());
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

void print_version()
{
    printf("%s %s\n", program_name(), CALLGRAPH_VERSION);
    if (g_mode != ProgramMode::Export) {
        printf("libbpf %d.%d\n", LIBBPF_MAJOR_VERSION, LIBBPF_MINOR_VERSION);
    }
    printf("otlp protobuf: %s\n", otlp_protobuf_available() ? "yes" : "no");
    printf("otlp http: %s\n", otlp_http_available() ? "yes" : "no");
    printf("static graph: external (callgraph-disasm)\n");

    struct utsname uts;
    if (uname(&uts) == 0)
        printf("kernel %s\n", uts.release);
}

void load_static_graphs(const std::vector<std::string>& paths,
                        StaticGraphDocument* document)
{
    for (const std::string& path : paths) {
        std::ifstream input(path, std::ios::binary);
        if (!input)
            fail("cannot open %s", path.c_str());
        std::string text((std::istreambuf_iterator<char>(input)),
                         std::istreambuf_iterator<char>());
        StaticGraphDocument part;
        std::string reason;
        if (!read_static_graph_json(text, &part, &reason))
            fail("cannot read %s: %s", path.c_str(), reason.c_str());
        for (auto& module : part.modules)
            document->modules.push_back(std::move(module));
    }
}

}  // namespace callgraph
