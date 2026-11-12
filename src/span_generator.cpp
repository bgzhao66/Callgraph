#include "callgraph/span_generator.h"

#include <cstdio>
#include <fstream>
#include <utility>

#include "callgraph/common.h"

namespace callgraph {
namespace {

uint64_t splitmix64(uint64_t value)
{
    value += 0x9e3779b97f4a7c15ULL;
    value = (value ^ (value >> 30)) * 0xbf58476d1ce4e5b9ULL;
    value = (value ^ (value >> 27)) * 0x94d049bb133111ebULL;
    return value ^ (value >> 31);
}

}  // namespace

bool parse_trace_scope(const std::string& text, TraceScope* scope)
{
    if (text == "root") {
        *scope = TraceScope::Root;
        return true;
    }
    if (text == "thread") {
        *scope = TraceScope::Thread;
        return true;
    }
    if (text == "process") {
        *scope = TraceScope::Process;
        return true;
    }
    return false;
}

const char* trace_scope_name(TraceScope scope)
{
    switch (scope) {
    case TraceScope::Root:
        return "root";
    case TraceScope::Thread:
        return "thread";
    case TraceScope::Process:
        return "process";
    }
    return "root";
}

SpanGenerator::SpanGenerator(SpanGeneratorConfig config, Emit emit)
    : config_(config),
      emit_(std::move(emit)),
      context_manager_(config.seed_hi, config.seed_lo)
{
}

bool SpanGenerator::sample_root(uint32_t tid, uint64_t sequence) const
{
    if (config_.sample_rate >= 1.0)
        return true;
    if (config_.sample_rate <= 0.0)
        return false;

    const uint64_t value =
        splitmix64(config_.seed_hi ^ (static_cast<uint64_t>(tid) << 32) ^
                   (sequence * 0x9e3779b97f4a7c15ULL));
    const uint64_t threshold =
        static_cast<uint64_t>(config_.sample_rate * 1000000.0);
    return (value % 1000000ULL) < threshold;
}

SpanGenerator::TraceInfo SpanGenerator::new_trace(uint32_t tid,
                                                  uint64_t sequence)
{
    TraceInfo info;
    info.trace_id = context_manager_.new_trace(tid, sequence);
    info.sampled = sample_root(tid, sequence);
    return info;
}

SpanGenerator::TraceInfo SpanGenerator::trace_for_thread(uint32_t tid)
{
    auto it = thread_traces_.find(tid);
    if (it != thread_traces_.end())
        return it->second;

    TraceInfo info = new_trace(tid, root_sequences_[tid]++);
    thread_traces_.emplace(tid, info);
    return info;
}

SpanGenerator::TraceInfo SpanGenerator::trace_for_process()
{
    if (!process_trace_initialized_) {
        process_trace_ = new_trace(0, 0);
        process_trace_initialized_ = true;
    }
    return process_trace_;
}

std::string SpanGenerator::thread_name(uint32_t tid)
{
    if (!config_.read_thread_names || config_.pid <= 0)
        return {};

    auto it = thread_names_.find(tid);
    if (it != thread_names_.end())
        return it->second;

    std::string name;
    const std::string path = "/proc/" + std::to_string(config_.pid) +
                             "/task/" + std::to_string(tid) + "/comm";
    std::ifstream input(path);
    if (input && std::getline(input, name)) {
        while (!name.empty() &&
               (name.back() == '\n' || name.back() == '\r'))
            name.pop_back();
    } else {
        log_verbose("cannot read thread name for tid %u (%s)", tid,
                    path.c_str());
        name.clear();
    }
    thread_names_.emplace(tid, name);
    return name;
}

uint64_t SpanGenerator::to_unix(uint64_t ts) const
{
    if (config_.timestamps_are_unix)
        return ts;
    if (config_.clock)
        return config_.clock->to_unix_ns(ts);
    return ts;
}

uint64_t SpanGenerator::on_function_enter(uint32_t tid, uint64_t function_id,
                                 uint32_t depth, uint64_t ts,
                                 const std::string& arguments,
                                 uint64_t parent_token)
{
    TraceInfo trace;
    if (parent_token != 0) {
        auto parent = open_.find(parent_token);
        if (parent != open_.end()) {
            trace.trace_id = parent->second.context.trace_id;
            trace.sampled = parent->second.sampled;
        } else {
            // The parent is unknown (for example after a stray event).  Treat
            // the call as a root rather than dropping the span.
            parent_token = 0;
            trace = config_.scope == TraceScope::Thread
                        ? trace_for_thread(tid)
                        : config_.scope == TraceScope::Process
                              ? trace_for_process()
                              : new_trace(tid, root_sequences_[tid]++);
        }
    } else {
        switch (config_.scope) {
        case TraceScope::Root:
            trace = new_trace(tid, root_sequences_[tid]++);
            break;
        case TraceScope::Thread:
            trace = trace_for_thread(tid);
            break;
        case TraceScope::Process:
            trace = trace_for_process();
            break;
        }
    }

    OpenSpan span;
    span.context.trace_id = trace.trace_id;
    span.context.span_id = context_manager_.next_span_id();
    span.context.parent_span_id = parent_token;
    span.function_id = function_id;
    span.tid = tid;
    span.depth = depth;
    span.start_ts = ts;
    span.sampled = trace.sampled;
    span.thread_name = thread_name(tid);
    span.arguments = arguments;

    const uint64_t token = span.context.span_id;
    open_.emplace(token, std::move(span));
    return token;
}

void SpanGenerator::on_function_exit(uint32_t tid, uint64_t token,
                             uint64_t function_id, uint64_t ts,
                             SpanCloseReason reason)
{
    (void)function_id;
    auto it = open_.find(token);
    if (it == open_.end())
        return;

    OpenSpan& open = it->second;
    if (!open.sampled) {
        ++spans_sampled_out_;
        open_.erase(it);
        return;
    }

    SpanRecord record;
    record.context = open.context;
    record.function_id = open.function_id;
    record.tid = tid;
    record.depth = open.depth;
    record.start_unix_ns = to_unix(open.start_ts);
    record.end_unix_ns = to_unix(ts);
    if (record.end_unix_ns < record.start_unix_ns)
        record.end_unix_ns = record.start_unix_ns;
    record.thread_name = open.thread_name;
    record.arguments = open.arguments;
    record.incomplete = reason != SpanCloseReason::Return;
    record.reason = reason;

    if (config_.functions && record.function_id < config_.functions->size())
        record.function = (*config_.functions)[record.function_id];
    if (record.function.name.empty())
        record.function.name = "unknown(" + std::to_string(record.function_id) + ")";

    open_.erase(it);
    ++spans_closed_;
    if (emit_)
        emit_(std::move(record));
}

}  // namespace callgraph
