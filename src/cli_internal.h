#pragma once

#include <fnmatch.h>
#include <sys/types.h>

#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <regex>
#include <string>
#include <vector>

#include "callgraph/common.h"
#include "callgraph/function_info.h"
#include "callgraph/static_graph_json.h"

namespace callgraph {

class OtelExporter;
class SpanGenerator;
struct OtelConfig;

// Which executable is running.  Set once at startup; it selects the help
// page and the diagnostic prefix.
enum class ProgramMode { Run, Attach, Export };

void set_program_mode(const char* argv0, ProgramMode mode);
ProgramMode program_mode();

// Help and diagnostics.
void usage(FILE* out);
void usage_brief(FILE* out);
[[noreturn]] void usage_error(const char* fmt, ...)
    __attribute__((format(printf, 1, 2)));
void print_version();

// Parse helpers shared by the live and offline grammars.
long parse_long(const std::string& text, const std::string& option);
size_t parse_size(const std::string& text, const std::string& option);
double parse_fraction(const std::string& text, const std::string& option);
double parse_quantile(const std::string& text, const std::string& option);
uint64_t parse_duration_ns(const std::string& text, const std::string& option);

struct Options {
    std::string command;
    pid_t pid = -1;
    std::string output;
    std::vector<std::string> root_scope;
    std::vector<std::string> exclude;
    bool use_regex = false;
    std::string return_mode = "uretprobe";
    bool no_rsp_resync = false;
    bool all_modules = false;
    std::vector<std::string> modules;
    std::vector<std::string> static_graph;
    bool wall_clock = false;
    int max_depth = -1;
    int trace_depth = -1;
    size_t indent_step = 0;
    bool show_args = false;
    bool histogram = false;
    double ingest_sample_rate = 1.0;
    uint64_t log_rate_limit = 0;
    bool kernel = false;
    bool sched = false;
    bool futex = false;
    bool io = false;
    bool block = false;
    bool memory = false;
    bool network = false;
    // Fine-grained scopes selected by presets.  The public --memory and
    // --network flags enable both of their sub-scopes.
    bool page_faults = false;
    bool tcp = false;
    bool require_kernel_events = false;
    uint64_t kernel_merge_window_ns = 1000000;
    std::string kernel_preset;
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
    bool complete_traces = false;
    double outlier_latency_quantile = 0.0;
    bool outlier_latency_quantile_set = false;
    size_t trace_buffer_bytes = 256ull << 20;
    size_t trace_buffer_spans = 1000000;
    bool trace_buffer_option_used = false;
    std::string trace_metadata;
};

// Help options use up to three levels: a master option, the options that

enum class ExportMode { Otel, Flame, Static };

struct ExportOptions {
    std::string input;
    std::string output;
    std::vector<std::string> static_graph;
    ExportMode mode = ExportMode::Otel;
    bool mode_set = false;
    bool help = false;
    bool version = false;
    bool otel_option_used = false;
    bool static_option_used = false;
    bool use_regex = false;
    std::vector<std::string> root_scope;
    std::string endpoint;
    std::string service_name;
    std::string service_namespace;
    std::string metadata_path;
    pid_t pid = 0;
    bool assume_local_capture = false;
    std::string trace_scope = "root";
    bool trace_scope_set = false;
    double sample_rate = 1.0;
    bool show_args = false;
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
    bool complete_traces = false;
    double outlier_latency_quantile = 0.0;
    bool outlier_latency_quantile_set = false;
    size_t trace_buffer_bytes = 256ull << 20;
    size_t trace_buffer_spans = 1000000;
    bool trace_buffer_option_used = false;
};

// Export help narrowed to the selected mode; the full page when unset.
void usage_export(FILE* out, ExportMode mode, bool mode_set);

// Shared offline/online helpers.
void load_static_graphs(const std::vector<std::string>& paths,
                        StaticGraphDocument* document);
std::string session_id_hex(uint64_t hi, uint64_t lo);
std::string normalize_otel_endpoint(std::string endpoint);
bool is_http_url(const std::string& endpoint);
void fill_host_otel_config(OtelConfig& config);
void print_otel_drop_stats(const OtelExporter& exporter);
void print_trace_buffer_stats(const SpanGenerator& generator);
void print_outlier_stats(const SpanGenerator& generator);
void print_kernel_span_stats(const SpanGenerator& generator);

class FunctionFilter {
public:
    FunctionFilter(const std::vector<std::string>& root_scope,
                   const std::vector<std::string>& exclude, bool use_regex)
        : root_scope_(root_scope), exclude_(exclude), use_regex_(use_regex)
    {
        if (use_regex_) {
            try {
                for (const auto& pattern : root_scope_)
                    root_scope_re_.emplace_back(pattern);
                for (const auto& pattern : exclude_)
                    exclude_re_.emplace_back(pattern);
            } catch (const std::regex_error& error) {
                fail("invalid regular expression: %s", error.what());
            }
        }
    }

    bool has_root_scope() const { return !root_scope_.empty(); }

    bool excluded(const FunctionInfo& function) const
    {
        return !exclude_.empty() &&
               matches(function, exclude_, exclude_re_);
    }

    // A root must match --root-scope and must not be excluded.
    bool root_match(const FunctionInfo& function) const
    {
        return !root_scope_.empty() &&
               matches(function.name, function.linkage_name, root_scope_,
                       root_scope_re_) &&
               !excluded(function);
    }

    // Name-based form used for facts that are not a FunctionInfo table.
    bool root_match_name(const std::string& name,
                         const std::string& linkage_name) const
    {
        return !root_scope_.empty() &&
               matches(name, linkage_name, root_scope_, root_scope_re_);
    }

private:
    static bool matches(const std::string& name,
                        const std::string& linkage_name,
                        const std::vector<std::string>& globs,
                        const std::vector<std::regex>& regexes)
    {
        for (const auto& pattern : globs) {
            if (fnmatch(pattern.c_str(), name.c_str(), 0) == 0)
                return true;
            if (fnmatch(pattern.c_str(), linkage_name.c_str(), 0) == 0)
                return true;
        }
        for (const auto& regex : regexes) {
            if (std::regex_search(name, regex))
                return true;
            if (std::regex_search(linkage_name, regex))
                return true;
        }
        return false;
    }

    static bool matches(const FunctionInfo& function,
                        const std::vector<std::string>& globs,
                        const std::vector<std::regex>& regexes)
    {
        return matches(function.name, function.linkage_name, globs, regexes);
    }

    std::vector<std::string> root_scope_;
    std::vector<std::string> exclude_;
    bool use_regex_;
    std::vector<std::regex> root_scope_re_;
    std::vector<std::regex> exclude_re_;
};

// Entry points for the three executables.
int trace_program(int argc, char** argv, ProgramMode mode);
int export_program(int argc, char** argv);

}  // namespace callgraph
