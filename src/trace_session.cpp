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
                   ProbeManager* probes, bool ret_mode,
                   const StaticGraphDocument* graph)
        : options_(options), filter_(filter), probes_(probes),
          ret_mode_(ret_mode), graph_(graph)
    {
    }

    bool add(const std::string& path, bool required, bool primary = false)
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

        StaticGraphFacts facts;
        bool have_facts = false;
        if (graph_) {
            const StaticGraphModule* source =
                find_static_graph_module(*graph_, module.build_id, path);
            if (source) {
                have_facts =
                    join_static_graph_module(*source, module.functions, &facts);
                if (!have_facts) {
                    log_verbose("--static-graph facts for %s match no "
                                "function; ignoring them",
                                path.c_str());
                }
            }
        }

        if (ret_mode_) {
            if (!have_facts || !facts.has_returns) {
                if (primary || required) {
                    fail("--return-mode=ret has no call-graph facts for %s; "
                         "regenerate with callgraph disasm (add --all-modules "
                         "to cover dependencies)",
                         path.c_str());
                }
                log_warn("--return-mode=ret: no call-graph facts for %s; "
                         "module is not traced",
                         path.c_str());
                return false;
            }
            apply_static_graph_returns(facts, &module.functions);
        }

        std::vector<size_t> candidates;
        std::vector<size_t> roots;
        candidates.reserve(module.functions.size());
        for (size_t i = 0; i < module.functions.size(); ++i) {
            if (filter_.excluded(module.functions[i]))
                continue;
            candidates.push_back(i);
            if (filter_.root_match(module.functions[i]))
                roots.push_back(i);
        }

        std::vector<size_t> keep = candidates;
        const int trace_depth = options_.trace_depth;
        if (trace_depth >= 0) {
            StaticPruneRequest request;
            request.module_path = path;
            request.functions = &module.functions;
            request.candidates = candidates;
            request.roots = roots;
            request.has_root_scope = filter_.has_root_scope();
            request.trace_depth = trace_depth;
            request.attach_mode = options_.command == "attach";
            request.is_go_binary = module.is_go_binary;
            request.verbose = options_.verbose;
            request.facts = have_facts ? &facts : nullptr;

            StaticPruneResult result =
                trace_depth == 0 ? select_roots(request)
                                 : prune_statically(request);
            if (result.available) {
                keep = std::move(result.keep);
                if (trace_depth > 0) {
                    log_info("static prune: kept %zu of %zu function(s) at "
                             "depth <= %d in %s (direct calls)",
                             keep.size(), candidates.size(), trace_depth,
                             path.c_str());
                }
            } else {
                instrumentation_incomplete_ = true;
                if (!roots.empty()) {
                    keep = roots;
                    log_warn("static call-graph analysis unavailable for %s "
                             "(%s); instrumenting only %zu explicitly scoped "
                             "root(s); descendants outside --root-scope will "
                             "not be traced",
                             path.c_str(), result.reason.c_str(), roots.size());
                } else {
                    keep.clear();
                    log_warn("static call-graph analysis unavailable for %s "
                             "(%s); user-function instrumentation is "
                             "incomplete. Instrumenting 0 functions. Use "
                             "--root-scope to specify tracing points "
                             "explicitly",
                             path.c_str(), result.reason.c_str());
                }
            }
        }

        std::vector<FunctionInfo> selected;
        selected.reserve(keep.size());
        for (const size_t index : keep)
            selected.push_back(std::move(module.functions[index]));

        if (selected.empty()) {
            if (required && trace_depth < 0)
                fail("no functions matched in %s", path.c_str());
            log_warn("no function probes instrumented in %s", path.c_str());
            modules_.push_back({path, {}});
            return true;
        }

        if (options_.show_args)
            annotate_parameters(path, selected);

        const size_t base = names_.size();
        for (size_t i = 0; i < selected.size(); ++i) {
            selected[i].function_id = base + i;
            if (filter_.root_match(selected[i])) {
                root_ids_.insert(selected[i].function_id);
                log_verbose("root: %s", selected[i].name.c_str());
            }
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

        if (probes_ && !selected.empty())
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
    const std::unordered_set<uint64_t>& root_ids() const
    {
        return root_ids_;
    }
    bool instrumentation_incomplete() const
    {
        return instrumentation_incomplete_;
    }

private:
    const Options& options_;
    FunctionFilter& filter_;
    ProbeManager* probes_;
    bool ret_mode_;
    const StaticGraphDocument* graph_;

    std::vector<std::string> names_;
    std::vector<FunctionSignature> signatures_;
    std::vector<FunctionMetadata> functions_;
    std::vector<PlannedModule> modules_;
    std::unordered_set<uint64_t> root_ids_;
    std::unordered_set<std::string> attached_;
    bool instrumentation_incomplete_ = false;
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

std::string canonical_executable(const std::string& program)
{
    std::string candidate = program;
    // execvp searches PATH for a bare name; mirror that before canonicalising
    // so the pre-flight lookup sees the same file.
    if (candidate.find('/') == std::string::npos) {
        const char* env = getenv("PATH");
        const std::string search = env ? env : "";
        size_t start = 0;
        while (start <= search.size()) {
            const size_t colon = search.find(':', start);
            const std::string dir =
                search.substr(start, colon == std::string::npos
                                         ? std::string::npos
                                         : colon - start);
            if (!dir.empty()) {
                const std::string full = dir + "/" + candidate;
                if (access(full.c_str(), X_OK) == 0) {
                    candidate = full;
                    break;
                }
            }
            if (colon == std::string::npos)
                break;
            start = colon + 1;
        }
    }
    std::error_code error;
    const auto canonical = std::filesystem::weakly_canonical(candidate, error);
    if (error)
        return candidate;
    return canonical.string();
}

// --return-mode=ret changes probe semantics, so a missing module or an empty
// return-offset table is fatal rather than a silent uretprobe downgrade.
void check_ret_facts(const StaticGraphDocument& graph,
                     const std::string& path)
{
    const StaticGraphModule* module =
        find_static_graph_module(graph, {}, path);
    if (!module) {
        fail("--static-graph has no facts for %s; regenerate with "
             "callgraph disasm (add --all-modules to cover dependencies)",
             path.c_str());
    }
    for (const auto& function : module->functions) {
        if (!function.return_offsets.empty())
            return;
    }
    fail("%s has no ret offsets in --static-graph", path.c_str());
}

std::vector<uint32_t> target_tids(pid_t pid)
{
    std::vector<uint32_t> tids;
    const std::string path = "/proc/" + std::to_string(pid) + "/task";
    std::error_code error;
    for (const auto& entry : std::filesystem::directory_iterator(path, error)) {
        const std::string name = entry.path().filename().string();
        char* end = nullptr;
        errno = 0;
        const unsigned long value = strtoul(name.c_str(), &end, 10);
        if (errno == 0 && end != name.c_str() && *end == '\0' &&
            value <= UINT32_MAX)
            tids.push_back(static_cast<uint32_t>(value));
    }
    return tids;
}


Options parse_trace_args(int argc, char** argv, ProgramMode mode)
{
    Options options;
    options.command = mode == ProgramMode::Run ? "run" : "attach";

    // Kernel sub-options are meaningless without --kernel.  Remember the first
    // one so the error can name it.
    std::string kernel_option_used;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];

        if (arg == "--" && mode != ProgramMode::Run)
            usage_error("attach takes -p <pid>, not a program");

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
        auto note_kernel_option = [&](const char* name) {
            if (kernel_option_used.empty())
                kernel_option_used = name;
        };
        auto add_kernel_family = [&](const std::string& name) {
            if (name == "sched") {
                options.sched = true;
            } else if (name == "futex") {
                options.futex = true;
            } else if (name == "io") {
                options.io = true;
            } else if (name == "block") {
                options.block = true;
            } else if (name == "net" || name == "network") {
                options.network = true;
                options.tcp = true;
            } else if (name == "mm" || name == "memory") {
                options.memory = true;
                options.page_faults = true;
            } else if (name == "all") {
                options.sched = true;
                options.futex = true;
                options.io = true;
                options.block = true;
                options.network = true;
                options.tcp = true;
                options.memory = true;
                options.page_faults = true;
            } else {
                usage_error("unknown kernel event family '%s'", name.c_str());
            }
        };

        if (arg == "-o" || arg == "--output") {
            options.output = value();
        } else if (arg == "--root-scope") {
            options.root_scope.push_back(value());
        } else if (arg == "--exclude") {
            options.exclude.push_back(value());
        } else if (arg == "--regex") {
            options.use_regex = true;
        } else if (arg == "--return-mode") {
            options.return_mode = value();
            if (options.return_mode != "uretprobe" && options.return_mode != "ret")
                usage_error("--return-mode must be 'uretprobe' or 'ret'");
        } else if (arg == "--no-rsp-resync") {
            options.no_rsp_resync = true;
        } else if (arg == "--all-modules") {
            options.all_modules = true;
        } else if (arg == "--static-graph") {
            options.static_graph.push_back(value());
        } else if (arg == "--module") {
            options.modules.push_back(value());
        } else if (arg == "-T" || arg == "--wall-clock") {
            options.wall_clock = true;
        } else if (arg == "--max-depth") {
            options.max_depth = static_cast<int>(parse_long(value(), arg));
        } else if (arg == "--trace-depth") {
            const long depth = parse_long(value(), arg);
            if (depth < 0)
                usage_error("--trace-depth must be >= 0");
            options.trace_depth = static_cast<int>(depth);
        } else if (arg == "--indent") {
            const long indent = parse_long(value(), arg);
            if (indent < 0)
                usage_error("--indent must be >= 0");
            options.indent_step = static_cast<size_t>(indent);
        } else if (arg == "--show-args") {
            options.show_args = true;
        } else if (arg == "--histogram") {
            options.histogram = true;
        } else if (arg == "--kernel") {
            options.kernel = true;
        } else if (arg == "--sched") {
            note_kernel_option("--sched");
            options.sched = true;
        } else if (arg == "--futex") {
            note_kernel_option("--futex");
            options.futex = true;
        } else if (arg == "--io") {
            note_kernel_option("--io");
            options.io = true;
        } else if (arg == "--block") {
            note_kernel_option("--block");
            options.block = true;
        } else if (arg == "--network") {
            note_kernel_option("--network");
            options.network = true;
            options.tcp = true;
        } else if (arg == "--memory") {
            note_kernel_option("--memory");
            options.memory = true;
            options.page_faults = true;
        } else if (arg == "--events") {
            note_kernel_option("--events");
            const std::string list = value();
            size_t start = 0;
            while (start <= list.size()) {
                const size_t comma = list.find(',', start);
                const std::string name =
                    list.substr(start, comma == std::string::npos
                                           ? std::string::npos
                                           : comma - start);
                if (name.empty())
                    usage_error("--events contains an empty family");
                add_kernel_family(name);
                if (comma == std::string::npos)
                    break;
                start = comma + 1;
            }
        } else if (arg == "--preset") {
            note_kernel_option("--preset");
            options.kernel_preset = value();
        } else if (arg == "--merge-window") {
            note_kernel_option("--merge-window");
            options.kernel_merge_window_ns = parse_duration_ns(value(), arg);
        } else if (arg == "--require-events") {
            note_kernel_option("--require-events");
            options.require_kernel_events = true;
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
            options.sample_rate = parse_fraction(value(), arg);
            mark_export_option();
        } else if (arg == "--ingest-sample-rate") {
            options.ingest_sample_rate = parse_fraction(value(), arg);
        } else if (arg == "--log-rate-limit") {
            options.log_rate_limit = parse_size(value(), arg);
        } else if (arg == "--outlier-latency-quantile") {
            options.outlier_latency_quantile = parse_quantile(value(), arg);
            options.outlier_latency_quantile_set = true;
            mark_export_option();
        } else if (arg == "--fail-on-export-error") {
            options.fail_on_export_error = true;
            mark_export_option();
        } else if (arg == "--complete-traces") {
            options.complete_traces = true;
            mark_export_option();
        } else if (arg == "--trace-buffer-bytes") {
            options.trace_buffer_bytes = parse_size(value(), arg);
            options.trace_buffer_option_used = true;
            mark_export_option();
        } else if (arg == "--trace-buffer-spans") {
            options.trace_buffer_spans = parse_size(value(), arg);
            options.trace_buffer_option_used = true;
            mark_export_option();
        } else if (arg == "--trace-metadata") {
            options.trace_metadata = value();
        } else if (arg == "-v" || arg == "--verbose") {
            options.verbose = true;
        } else if (arg == "-p" || arg == "--pid") {
            if (mode != ProgramMode::Attach)
                usage_error("-p/--pid is only valid for callgraph attach");
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

    if (mode == ProgramMode::Run && options.program.empty())
        usage_error("a program is required (use -- before it)");
    if (mode == ProgramMode::Attach && options.pid <= 0)
        usage_error("attach requires -p <pid>");

    if (!options.kernel && !kernel_option_used.empty())
        usage_error("%s requires --kernel", kernel_option_used.c_str());

    // --kernel on its own selects the default latency preset; an explicit
    // family or preset overrides it.
    if (options.kernel && options.kernel_preset.empty() && !options.sched &&
        !options.futex && !options.io && !options.block && !options.memory &&
        !options.network) {
        options.kernel_preset = "latency";
    }

    // Presets enable fine-grained scopes.  They are additive: an explicit
    // --memory/--network (or --events mm/net) still adds its sub-scope.
    if (!options.kernel_preset.empty()) {
        if (options.kernel_preset == "latency") {
            options.sched = true;
            options.futex = true;
            options.io = true;
            options.network = true;
        } else if (options.kernel_preset == "proxy") {
            options.sched = true;
            options.futex = true;
            options.io = true;
            options.memory = true;
            options.network = true;
            options.tcp = true;
        } else if (options.kernel_preset == "storage") {
            options.sched = true;
            options.futex = true;
            options.io = true;
            options.memory = true;
        } else if (options.kernel_preset == "computation") {
            options.sched = true;
            options.futex = true;
            options.memory = true;
            options.page_faults = true;
        } else if (options.kernel_preset == "full") {
            options.sched = true;
            options.futex = true;
            options.io = true;
            options.memory = true;
            options.page_faults = true;
            options.network = true;
            options.tcp = true;
        } else if (options.kernel_preset == "extended") {
            options.sched = true;
            options.futex = true;
            options.io = true;
            options.block = true;
            options.memory = true;
            options.page_faults = true;
            options.network = true;
            options.tcp = true;
        } else {
            usage_error("--preset must be 'latency', 'proxy', 'storage', "
                        "'computation', 'full', or 'extended'");
        }
    }
    const bool kernel_any = options.sched || options.futex || options.io ||
                            options.block || options.memory ||
                            options.network || options.page_faults ||
                            options.tcp;
    if (options.require_kernel_events && !kernel_any)
        usage_error("--require-events requires a kernel event family");
    if (options.kernel_merge_window_ns == 0)
        usage_error("--merge-window must be > 0");

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
    if (options.trace_buffer_option_used && !options.complete_traces)
        usage_error("--trace-buffer options require --complete-traces");
    if (options.outlier_latency_quantile_set && !options.complete_traces)
        usage_error("--outlier-latency-quantile requires --complete-traces");
    if (options.complete_traces) {
        if (options.trace_buffer_bytes == 0 ||
            options.trace_buffer_spans == 0)
            usage_error("--trace-buffer limits must be >= 1");
    }
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
    if (options.return_mode == "ret" && options.static_graph.empty())
        usage_error("--return-mode=ret requires --static-graph <file> (produce "
                    "it with callgraph disasm)");
    if (options.return_mode != "ret" && options.trace_depth < 0 &&
        !options.static_graph.empty()) {
        log_warn("--static-graph is only used by --trace-depth and "
                 "--return-mode=ret; ignoring it");
    }
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
}  // namespace

int trace_program(int argc, char** argv, ProgramMode mode)
{
    try {
        set_program_mode(argv[0], mode);
        const Options options = parse_trace_args(argc, argv, mode);
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

        StaticGraphDocument static_graph;
        if (!options.static_graph.empty())
            load_static_graphs(options.static_graph, &static_graph);

        const bool ret_mode = options.return_mode == "ret";
        if (ret_mode && options.command == "run" && !options.program.empty()) {
            check_ret_facts(static_graph,
                            canonical_executable(options.program[0]));
        }

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

        if (ret_mode && options.command == "attach")
            check_ret_facts(static_graph, exe);

        FunctionFilter filter(options.root_scope, options.exclude,
                              options.use_regex);

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
            ModuleRegistry registry(options, filter, nullptr, false,
                                    &static_graph);
            registry.add(exe, !multi_module, true);
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
        // Rate limiting is a stdout convenience; file output and the
        // histogram trailer keep their complete line stream.
        const bool log_rate_limit_enabled =
            (options.output.empty() || options.output == "-") &&
            options.log_rate_limit != 0;
        if (log_rate_limit_enabled)
            output.set_log_rate_limit(options.log_rate_limit);

        ProbeManager probes(target, options.ringbuf_size, options.probe_batch_size,
                            options.verbose);
        probes.load();
        probes.set_capture_arguments(options.show_args);

        KernelSelection kernel_selection;
        kernel_selection.sched = options.sched;
        kernel_selection.futex = options.futex;
        kernel_selection.io = options.io;
        kernel_selection.block = options.block;
        kernel_selection.memory = options.memory;
        kernel_selection.network = options.network;
        kernel_selection.page_faults = options.page_faults;
        kernel_selection.tcp = options.tcp;

        std::unique_ptr<KernelProbeManager> kernel_probes;
        std::unique_ptr<KernelTimeline> kernel_timeline;
        if (kernel_selection.any()) {
            const std::vector<uint32_t> tids = target_tids(target);
            kernel_probes = std::make_unique<KernelProbeManager>(
                options.ringbuf_size, options.verbose);
            kernel_probes->load();
            kernel_probes->set_system_wide(false);
            kernel_probes->set_target_tids(tids);
            kernel_probes->attach(kernel_selection,
                                 options.require_kernel_events);
            kernel_timeline = std::make_unique<KernelTimeline>(
                output, options.max_depth, options.verbose);
            kernel_timeline->set_target_tids(tids);
            kernel_timeline->set_collect_histograms(options.histogram);
            if (options.block)
                log_warn("block tracepoints are global; unrelated device "
                         "traffic may be included");
            log_info("kernel events: %llu tracepoint(s) attached, %llu "
                     "unavailable",
                     static_cast<unsigned long long>(
                         kernel_probes->attached_events()),
                     static_cast<unsigned long long>(
                         kernel_probes->missing_events()));
        }

        ModuleRegistry registry(options, filter, &probes, ret_mode,
                                &static_graph);
        registry.add(exe, !multi_module, true);
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
            otel_config.queue_bytes = options.complete_traces
                                          ? options.trace_buffer_bytes
                                          : 0;
            if (options.complete_traces)
                otel_config.queue_spans =
                    std::max(options.queue_spans, options.trace_buffer_spans);
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
            builder_config.complete_traces = options.complete_traces;
            builder_config.outlier_quantile = options.outlier_latency_quantile;
            builder_config.trace_buffer_bytes = options.trace_buffer_bytes;
            builder_config.trace_buffer_spans = options.trace_buffer_spans;
            span_generator = std::make_unique<SpanGenerator>(
                builder_config,
                [&exporter](SpanRecord&& span) {
                    (*exporter).export_span(std::move(span));
                },
                [&exporter](std::vector<SpanRecord>&& spans) {
                    (*exporter).export_trace(std::move(spans));
                });
        }

        if (kernel_timeline && span_generator)
            kernel_timeline->set_kernel_span_sink(span_generator.get());

        if (registry.names().empty())
            log_info("no functions matched yet; waiting for matching modules to load");

        CallStack stack(registry.names(),
                        options.show_args ? &registry.signatures() : nullptr,
                        output, options.max_depth, options.verbose,
                        options.histogram, span_generator.get());
        stack.set_rsp_resync(!options.no_rsp_resync);
        stack.set_trace_depth(options.trace_depth);
        stack.set_trace_roots(&registry.root_ids(), filter.has_root_scope());
        stack.set_ingest_sample_rate(options.ingest_sample_rate);

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
        uint64_t last_target_refresh_ns = last_calibration_ns;
        uint64_t last_rate_report_ns = last_calibration_ns;
        constexpr uint64_t kRateLimitReportIntervalNs = 5000000000ULL;
        auto collector_tick = [&]() {
            refresh_modules();
            const uint64_t now = ClockConverter::now_monotonic_ns();
            if (kernel_probes && now - last_target_refresh_ns >= 250000000ULL) {
                const std::vector<uint32_t> tids = target_tids(target);
                kernel_probes->set_target_tids(tids);
                kernel_timeline->set_target_tids(tids);
                last_target_refresh_ns = now;
            }
            if (log_rate_limit_enabled &&
                now - last_rate_report_ns >= kRateLimitReportIntervalNs) {
                const auto report = output.take_rate_limit_report();
                if (report.total() != 0) {
                    fprintf(stderr,
                            "callgraph: suppressed %" PRIu64
                            " event line(s) by rate-limit since last report "
                            "(user %" PRIu64 ", kernel %" PRIu64 ")\n",
                            report.total(), report.user, report.kernel);
                }
                last_rate_report_ns = now;
            }
            if (now - last_calibration_ns >= 30000000000ULL) {
                clock_converter.recalibrate();
                last_calibration_ns = now;
            }
        };

        EventCollector collector(
            probes.events_fd(), stack,
            kernel_probes ? kernel_probes->events_fd() : -1,
            kernel_timeline.get(), options.kernel_merge_window_ns,
            [&](uint32_t tid) {
                if (kernel_probes)
                    kernel_probes->add_target_tid(tid);
                if (kernel_timeline)
                    kernel_timeline->add_target_tid(tid);
            });
        collector.run(target, is_child ? target : -1, collector_tick);

        std::string report;
        if (kernel_timeline) {
            kernel_timeline->finish(ClockConverter::now_monotonic_ns(), stack);
            kernel_timeline->set_kernel_span_sink(nullptr);
        }
        if (options.histogram) {
            stack.finish_statistics();
            const auto* kernel_histograms =
                kernel_timeline ? &kernel_timeline->kernel_histograms()
                                : nullptr;
            report = format_histogram_report(stack.stats(), registry.names(),
                                             kernel_histograms);
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
            print_otel_drop_stats(*exporter);
        }
        if (span_generator && span_generator->spans_sampled_out() != 0) {
            fprintf(stderr, "callgraph: sampled out %" PRIu64 " span(s)\n",
                    span_generator->spans_sampled_out());
        }
        if (stack.ingest_skipped_roots() != 0) {
            fprintf(stderr,
                    "callgraph: ingest-sampled out %" PRIu64
                    " root trace(s)\n",
                    stack.ingest_skipped_roots());
        }
        const uint64_t rate_limited_user = output.user_lines_suppressed();
        const uint64_t rate_limited_kernel = output.kernel_lines_suppressed();
        if (rate_limited_user + rate_limited_kernel != 0) {
            fprintf(stderr,
                    "callgraph: suppressed %" PRIu64
                    " event line(s) by rate-limit total (user %" PRIu64
                    ", kernel %" PRIu64 ")\n",
                    rate_limited_user + rate_limited_kernel, rate_limited_user,
                    rate_limited_kernel);
        }
        if (span_generator && options.complete_traces)
            print_trace_buffer_stats(*span_generator);
        if (span_generator)
            print_outlier_stats(*span_generator);
        if (span_generator)
            print_kernel_span_stats(*span_generator);

        const uint64_t lost = probes.lost_events();
        const uint64_t events = stack.entries() + stack.returns();
        const uint64_t kernel_lost =
            kernel_probes ? kernel_probes->lost_events() : 0;
        const uint64_t kernel_events =
            kernel_timeline ? kernel_timeline->kernel_events() : 0;

        fprintf(stderr,
                "callgraph: %" PRIu64 " events, %" PRIu64 " entries, "
                "%" PRIu64 " returns, %" PRIu64 " lost, %" PRIu64
                " desync, %" PRIu64 " stray, %" PRIu64 " dropped\n",
                events, stack.entries(), stack.returns(), lost, stack.desyncs(),
                stack.stray_returns(), output.dropped());
        if (kernel_probes) {
            fprintf(stderr,
                    "callgraph: %" PRIu64 " kernel events, %" PRIu64
                    " kernel seen, %" PRIu64
                    " kernel lost, %" PRIu64 " kernel dropped, %" PRIu64
                    " kernel tracepoints\n",
                    kernel_events, collector.kernel_events_seen(), kernel_lost,
                    output.dropped_kernel(),
                    kernel_probes->attached_events());
        }
        if (registry.instrumentation_incomplete()) {
            log_warn("user-function instrumentation is incomplete; see the "
                     "static-analysis warnings above");
        }

        if (lost != 0)
            log_warn("ring buffer overflowed: the trace is incomplete");
        if (kernel_lost != 0)
            log_warn("kernel ring buffer overflowed: kernel attribution is "
                     "incomplete");
        if (probes.attach_failures() != 0)
            log_warn("%" PRIu64 " probe(s) failed to attach",
                     probes.attach_failures());

        if (exporter && options.fail_on_export_error && exporter->failed() != 0)
            return 1;
        return 0;
    } catch (const std::exception& error) {
        fprintf(stderr, "%s: %s\n", program_name(), error.what());
        return 1;
    }
}
}  // namespace callgraph
