#include <fnmatch.h>
#include <signal.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <unistd.h>

#include <bpf/libbpf_version.h>

#include <cerrno>
#include <cinttypes>
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <regex>
#include <string>
#include <unordered_set>
#include <utility>
#include <vector>

#include "callgraph/call_stack.h"
#include "callgraph/common.h"
#include "callgraph/elf_resolver.h"
#include "callgraph/event_collector.h"
#include "callgraph/module_manager.h"
#include "callgraph/output.h"
#include "callgraph/process_controller.h"
#include "callgraph/probe_manager.h"

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
    size_t batch_size = 1000;
    size_t ringbuf_size = 16ull << 20;
    bool dry_run = false;
    bool verbose = false;
    bool help = false;
    bool version = false;
    std::vector<std::string> program;
};

void usage(FILE* out)
{
    fprintf(out,
            "Usage:\n"
            "  callgraph run [options] -- program [args...]\n"
            "  callgraph attach [options] -p PID\n"
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
            "      --batch-size N    functions per uprobe_multi link (default: 1000)\n"
            "      --ringbuf-size N  ring buffer size, k/m/g suffix (default: 16m)\n"
            "      --dry-run         list resolved functions and exit\n"
            "  -v, --verbose         verbose diagnostics\n"
            "  -h, --help            show this help\n"
            "      --version         show version\n"
            "\n"
            "Examples:\n"
            "  sudo callgraph run -- ./demo\n"
            "  sudo callgraph attach -p 12345 --include 'Database::*'\n"
            "  callgraph run --dry-run -- ./demo\n");
}

[[noreturn]] void usage_error(const char* fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    fprintf(stderr, "callgraph: ");
    vfprintf(stderr, fmt, ap);
    fprintf(stderr, "\n\n");
    va_end(ap);
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
        } else if (arg == "--batch-size") {
            options.batch_size = static_cast<size_t>(parse_long(value(), arg));
        } else if (arg == "--ringbuf-size") {
            options.ringbuf_size = parse_size(value(), arg);
        } else if (arg == "--dry-run") {
            options.dry_run = true;
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
    if (options.batch_size == 0)
        usage_error("--batch-size must be >= 1");
#ifndef CALLGRAPH_HAVE_LIBOPCODES
    if (options.return_mode == "ret")
        usage_error("--return-mode=ret requires libopcodes (install binutils-dev "
                    "and rebuild)");
#endif

    const long page_size = sysconf(_SC_PAGESIZE);
    const size_t rb = options.ringbuf_size;
    if (rb < 4096 || (rb & (rb - 1)) != 0 ||
        (page_size > 0 && rb % static_cast<size_t>(page_size) != 0))
        usage_error("--ringbuf-size must be a power of two and a multiple of "
                    "the page size");

    return options;
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

        const size_t base = names_.size();
        for (size_t i = 0; i < selected.size(); ++i) {
            selected[i].function_id = base + i;
            names_.push_back(selected[i].name);
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

        modules_.push_back({path, std::move(selected)});
        return true;
    }

    const std::vector<std::string>& names() const { return names_; }
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
    std::vector<PlannedModule> modules_;
    std::unordered_set<std::string> attached_;
    bool warned_exceptions_ = false;
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

    struct utsname uts;
    if (uname(&uts) == 0)
        printf("kernel %s\n", uts.release);
}

}  // namespace

int main(int argc, char** argv)
{
    try {
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

        Output output(options.output, options.wall_clock
                                          ? TimestampMode::WallClock
                                          : TimestampMode::BootSeconds,
                      options.indent_step);
        ProbeManager probes(target, options.ringbuf_size, options.batch_size,
                            options.verbose);
        probes.load();

        const bool ret_mode = options.return_mode == "ret";
        ModuleRegistry registry(options, filter, &probes, ret_mode);
        registry.add(exe, !multi_module);
        for (size_t i = 1; i < initial_paths.size(); ++i)
            registry.add(initial_paths[i], false);

        if (registry.names().empty())
            log_info("no functions matched yet; waiting for matching modules to load");

        CallStack stack(registry.names(), output, options.max_depth,
                        options.verbose);

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

        EventCollector collector(probes.events_fd(), stack);
        collector.run(target, is_child ? target : -1, refresh_modules);
        output.stop();

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

        return 0;
    } catch (const std::exception& error) {
        fprintf(stderr, "callgraph: %s\n", error.what());
        return 1;
    }
}
