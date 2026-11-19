#include "callgraph/kernel_timeline.h"

#include <cinttypes>
#include <cstdio>
#include <iterator>
#include <span>
#include <utility>

#include "callgraph/call_stack.h"
#include "callgraph/common.h"
#include "callgraph/output.h"

namespace callgraph {
namespace {

constexpr uint32_t kFutexWait = 0;
constexpr uint32_t kFutexWaitBitset = 9;
constexpr uint32_t kFutexWaitRequeuePi = 11;
constexpr uint32_t kFutexWake = 1;
constexpr uint32_t kFutexWakeBitset = 10;

bool futex_is_wait(uint32_t op)
{
    const uint32_t cmd = op & 0x7f;
    return cmd == kFutexWait || cmd == kFutexWaitBitset ||
           cmd == kFutexWaitRequeuePi;
}

bool futex_is_wake(uint32_t op)
{
    const uint32_t cmd = op & 0x7f;
    return cmd == kFutexWake || cmd == kFutexWakeBitset;
}

void append_attr(std::string& attrs, const char* key, uint64_t value)
{
    if (!attrs.empty())
        attrs.push_back(' ');
    attrs += key;
    attrs.push_back('=');
    attrs += std::to_string(value);
}

void append_signed_attr(std::string& attrs, const char* key, int64_t value)
{
    if (!attrs.empty())
        attrs.push_back(' ');
    attrs += key;
    attrs.push_back('=');
    attrs += std::to_string(value);
}

void append_hex_attr(std::string& attrs, const char* key, uint64_t value)
{
    if (!attrs.empty())
        attrs.push_back(' ');
    char buffer[32];
    snprintf(buffer, sizeof(buffer), "%s=0x%" PRIx64, key, value);
    attrs += buffer;
}

void append_text_attr(std::string& attrs, const char* key,
                      const std::string& value)
{
    if (!attrs.empty())
        attrs.push_back(' ');
    attrs += key;
    attrs.push_back('=');
    attrs += value;
}

std::string kernel_attribute_key(const char* name)
{
    return std::string("callgraph.kernel.") + name;
}

void add_string_attr(std::vector<SpanAttribute>& attributes, const char* key,
                     std::string value)
{
    attributes.push_back(
        make_span_string(kernel_attribute_key(key), std::move(value)));
}

void add_int_attr(std::vector<SpanAttribute>& attributes, const char* key,
                  int64_t value)
{
    attributes.push_back(make_span_int(kernel_attribute_key(key), value));
}

void add_uint_attr(std::vector<SpanAttribute>& attributes, const char* key,
                   uint64_t value)
{
    add_int_attr(attributes, key, static_cast<int64_t>(value));
}

void add_bool_attr(std::vector<SpanAttribute>& attributes, const char* key,
                   bool value)
{
    attributes.push_back(make_span_bool(kernel_attribute_key(key), value));
}

void add_hex_attr(std::vector<SpanAttribute>& attributes, const char* key,
                  uint64_t value)
{
    char buffer[32];
    snprintf(buffer, sizeof(buffer), "0x%" PRIx64, value);
    add_string_attr(attributes, key, buffer);
}

void add_common_span_attrs(std::vector<SpanAttribute>& attributes,
                           const char* event, uint32_t user_depth)
{
    (void)user_depth;
    add_string_attr(attributes, "event", event);
    add_string_attr(attributes, "attribution", "direct");
}

enum class ArgFormat { Int, Signed, Hex };

struct ArgSpec {
    const char* name;
    uint8_t field;  // 1 = event.b, ..., 7 = event.h
    ArgFormat format;
};

uint64_t arg_value(const KernelEvent& event, uint8_t field)
{
    switch (field) {
    case 1:
        return event.b;
    case 2:
        return event.c;
    case 3:
        return event.d;
    case 4:
        return event.e;
    case 5:
        return event.f;
    case 6:
        return event.g;
    case 7:
        return event.h;
    default:
        return 0;
    }
}

void add_arg_attr(std::vector<SpanAttribute>& attributes,
                  const ArgSpec& spec, const KernelEvent& event)
{
    const uint64_t value = arg_value(event, spec.field);
    switch (spec.format) {
    case ArgFormat::Int:
        add_uint_attr(attributes, spec.name, value);
        break;
    case ArgFormat::Signed:
        add_int_attr(attributes, spec.name, static_cast<int32_t>(value));
        break;
    case ArgFormat::Hex:
        add_hex_attr(attributes, spec.name, value);
        break;
    }
}

constexpr ArgSpec kFutexArgs[] = {
    {"uaddr", 1, ArgFormat::Hex}, {"op", 2, ArgFormat::Hex},
    {"val", 3, ArgFormat::Int},   {"utime", 4, ArgFormat::Hex},
    {"uaddr2", 5, ArgFormat::Hex}, {"val3", 6, ArgFormat::Int},
};
constexpr ArgSpec kReadArgs[] = {
    {"fd", 1, ArgFormat::Signed},
    {"buf", 2, ArgFormat::Hex},
    {"count", 3, ArgFormat::Int},
};
constexpr ArgSpec kPreadArgs[] = {
    {"fd", 1, ArgFormat::Signed},
    {"buf", 2, ArgFormat::Hex},
    {"count", 3, ArgFormat::Int},
    {"pos", 4, ArgFormat::Int},
};
constexpr ArgSpec kFdArgs[] = {
    {"fd", 1, ArgFormat::Signed},
};
constexpr ArgSpec kOpenatArgs[] = {
    {"dfd", 1, ArgFormat::Signed},
    {"filename", 2, ArgFormat::Hex},
    {"flags", 3, ArgFormat::Hex},
    {"mode", 4, ArgFormat::Int},
};
constexpr ArgSpec kSyncFileRangeArgs[] = {
    {"fd", 1, ArgFormat::Signed},
    {"offset", 2, ArgFormat::Int},
    {"nbytes", 3, ArgFormat::Int},
    {"flags", 4, ArgFormat::Hex},
};
constexpr ArgSpec kSocketArgs[] = {
    {"family", 1, ArgFormat::Int},
    {"type", 2, ArgFormat::Int},
    {"protocol", 3, ArgFormat::Int},
};
constexpr ArgSpec kConnectArgs[] = {
    {"fd", 1, ArgFormat::Signed},
    {"addr", 2, ArgFormat::Hex},
    {"addrlen", 3, ArgFormat::Signed},
};
constexpr ArgSpec kAccept4Args[] = {
    {"fd", 1, ArgFormat::Signed},
    {"addr", 2, ArgFormat::Hex},
    {"addrlen", 3, ArgFormat::Hex},
    {"flags", 4, ArgFormat::Hex},
};
constexpr ArgSpec kSendtoArgs[] = {
    {"fd", 1, ArgFormat::Signed},   {"buf", 2, ArgFormat::Hex},
    {"len", 3, ArgFormat::Int},     {"flags", 4, ArgFormat::Hex},
    {"addr", 5, ArgFormat::Hex},    {"addr_len", 6, ArgFormat::Signed},
};
constexpr ArgSpec kRecvfromArgs[] = {
    {"fd", 1, ArgFormat::Signed},   {"buf", 2, ArgFormat::Hex},
    {"size", 3, ArgFormat::Int},    {"flags", 4, ArgFormat::Hex},
    {"addr", 5, ArgFormat::Hex},    {"addr_len", 6, ArgFormat::Hex},
};
constexpr ArgSpec kMsgArgs[] = {
    {"fd", 1, ArgFormat::Signed},
    {"msg", 2, ArgFormat::Hex},
    {"flags", 3, ArgFormat::Hex},
};
constexpr ArgSpec kEpollWaitArgs[] = {
    {"epfd", 1, ArgFormat::Signed},
    {"events", 2, ArgFormat::Hex},
    {"maxevents", 3, ArgFormat::Int},
    {"timeout", 4, ArgFormat::Signed},
};
constexpr ArgSpec kPollArgs[] = {
    {"fds", 1, ArgFormat::Hex},
    {"nfds", 2, ArgFormat::Int},
    {"timeout", 3, ArgFormat::Signed},
};

std::span<const ArgSpec> enter_arg_specs(uint16_t kind)
{
    switch (kind) {
    case CG_KEV_FUTEX_ENTER:
        return kFutexArgs;
    case CG_KEV_READ_ENTER:
    case CG_KEV_WRITE_ENTER:
        return kReadArgs;
    case CG_KEV_PREAD64_ENTER:
    case CG_KEV_PWRITE64_ENTER:
        return kPreadArgs;
    case CG_KEV_FSYNC_ENTER:
    case CG_KEV_FDATASYNC_ENTER:
    case CG_KEV_CLOSE_ENTER:
        return kFdArgs;
    case CG_KEV_OPENAT_ENTER:
        return kOpenatArgs;
    case CG_KEV_SYNC_FILE_RANGE_ENTER:
        return kSyncFileRangeArgs;
    case CG_KEV_NET_SOCKET_ENTER:
        return kSocketArgs;
    case CG_KEV_NET_CONNECT_ENTER:
        return kConnectArgs;
    case CG_KEV_NET_ACCEPT4_ENTER:
        return kAccept4Args;
    case CG_KEV_NET_SENDTO_ENTER:
        return kSendtoArgs;
    case CG_KEV_NET_RECVFROM_ENTER:
        return kRecvfromArgs;
    case CG_KEV_NET_SENDMSG_ENTER:
    case CG_KEV_NET_RECVMSG_ENTER:
        return kMsgArgs;
    case CG_KEV_NET_EPOLL_WAIT_ENTER:
        return kEpollWaitArgs;
    case CG_KEV_NET_POLL_ENTER:
        return kPollArgs;
    default:
        return {};
    }
}

std::string syscall_name(uint16_t enter_kind)
{
    if (enter_kind == CG_KEV_FUTEX_ENTER)
        return "futex";
    const char* name = kernel_is_net_enter(enter_kind)
                           ? kernel_net_event_name(enter_kind)
                           : kernel_io_event_name(enter_kind);
    std::string value = name ? name : "syscall";
    constexpr const char* suffix = "_begin";
    if (value.size() > 6 &&
        value.compare(value.size() - 6, 6, suffix) == 0)
        value.resize(value.size() - 6);
    return value;
}

std::string syscall_span_name(uint16_t enter_kind)
{
    return "@" + syscall_name(enter_kind);
}

int depth_of(const CallStack& stack, uint32_t tid)
{
    const auto frames = stack.traced_frames_for(tid);
    if (frames.empty())
        return kKernelDepthNone;
    return static_cast<int>(frames.size() - 1);
}

uint32_t span_user_depth(const CallStack& stack, uint32_t tid)
{
    const int depth = depth_of(stack, tid);
    return depth < 0 ? 0 : static_cast<uint32_t>(depth);
}

std::string device_text(uint64_t value)
{
    const uint32_t dev = static_cast<uint32_t>(value);
    const uint32_t major = dev >> 20;
    const uint32_t minor = dev & ((1U << 20) - 1);
    return std::to_string(major) + ":" + std::to_string(minor);
}

std::string ipv4_text(uint64_t value)
{
    const uint32_t address = static_cast<uint32_t>(value);
    return std::to_string(address & 0xff) + "." +
           std::to_string((address >> 8) & 0xff) + "." +
           std::to_string((address >> 16) & 0xff) + "." +
           std::to_string((address >> 24) & 0xff);
}

}  // namespace

const char* block_reason_name(BlockReason reason)
{
    switch (reason) {
    case BlockReason::None:
        return "none";
    case BlockReason::Futex:
        return "futex";
    case BlockReason::Io:
        return "io";
    case BlockReason::Net:
        return "net";
    case BlockReason::Memory:
        return "memory";
    case BlockReason::Uninterruptible:
        return "uninterruptible";
    case BlockReason::Sleep:
        return "sleep";
    case BlockReason::Other:
        return "other";
    }
    return "other";
}

size_t KernelTimeline::BlockKeyHash::operator()(
    const BlockKey& key) const noexcept
{
    uint64_t hash = key.dev * 0x9e3779b97f4a7c15ULL;
    hash ^= key.sector + 0x9e3779b97f4a7c15ULL + (hash << 6) + (hash >> 2);
    hash ^= key.nr_sector + 0x9e3779b97f4a7c15ULL + (hash << 6) + (hash >> 2);
    return static_cast<size_t>(hash);
}

KernelTimeline::KernelTimeline(Output& output, int max_depth, bool verbose)
    : output_(output), max_depth_(max_depth), verbose_(verbose)
{
}

void KernelTimeline::set_target_tids(const std::vector<uint32_t>& tids)
{
    targets_.insert(tids.begin(), tids.end());
}

void KernelTimeline::add_target_tid(uint32_t tid)
{
    targets_.insert(tid);
}

bool KernelTimeline::is_target(uint32_t tid) const
{
    return targets_.count(tid) != 0;
}

uint64_t KernelTimeline::next_id()
{
    return next_id_++;
}

void KernelTimeline::record_kernel_histogram(uint32_t tid,
                                             const CallStack& stack,
                                             const std::string& event,
                                             uint64_t ns, bool incomplete)
{
    if (!collect_histograms_)
        return;

    const auto frames = stack.traced_frames_for(tid);
    if (frames.empty())
        return;

    CallPath path;
    path.reserve(frames.size());
    for (const CallFrame& frame : frames)
        path.push_back(frame.function_id);

    KernelHistogram& entry = kernel_histograms_[tid][std::move(path)][event];
    entry.histogram.add(ns);
    entry.incomplete = entry.incomplete || incomplete;
}

void KernelTimeline::set_pmu_event_names(std::vector<std::string> names)
{
    pmu_event_names_ = std::move(names);
}

void KernelTimeline::record_pmu_histogram(uint32_t tid, const CallStack& stack,
                                          const std::string& event,
                                          uint64_t period)
{
    if (!collect_histograms_)
        return;

    const auto frames = stack.traced_frames_for(tid);
    if (frames.empty())
        return;

    CallPath path;
    path.reserve(frames.size());
    for (const CallFrame& frame : frames)
        path.push_back(frame.function_id);

    PmuHistogram& entry = pmu_histograms_[tid][std::move(path)][event];
    entry.samples += 1;
    entry.events += period;
}

void KernelTimeline::on_pmu_sample(const PmuSample& sample,
                                   const CallStack& stack)
{
    if (exited_.count(sample.tid) != 0 || !is_target(sample.tid))
        return;

    ++pmu_samples_;

    const std::string name =
        sample.event_index < pmu_event_names_.size()
            ? pmu_event_names_[sample.event_index]
            : "event" + std::to_string(sample.event_index);

    std::string attrs;
    append_text_attr(attrs, "event", name);
    append_attr(attrs, "period", sample.period);
    append_hex_attr(attrs, "ip", sample.ip);
    append_attr(attrs, "cpu", sample.cpu);
    append_attr(attrs, "approximate", 1);
    if (sample.timestamp_from_receipt)
        append_attr(attrs, "receipt_time", 1);

    KernelEvent event = {};
    event.ts = sample.ts;
    event.tid = sample.tid;
    event.category = CG_KCAT_PMU;
    event.kind = CG_KEV_PMU_SAMPLE;
    emit_event(event, depth_of(stack, sample.tid),
               kernel_kind_name(event.kind), attrs);

    if (collect_histograms_)
        record_pmu_histogram(sample.tid, stack, name, sample.period);

    const auto frames = stack.traced_frames_for(sample.tid);
    if (span_sink_ && !frames.empty()) {
        const uint32_t user_depth =
            static_cast<uint32_t>(frames.size() - 1);
        char ip[32];
        snprintf(ip, sizeof(ip), "0x%" PRIx64, sample.ip);
        std::vector<SpanAttribute> span_attrs;
        span_attrs.push_back(make_span_string("callgraph.pmu.event", name));
        span_attrs.push_back(make_span_int(
            "callgraph.pmu.period", static_cast<int64_t>(sample.period)));
        span_attrs.push_back(make_span_string("callgraph.pmu.ip", ip));
        span_attrs.push_back(
            make_span_int("callgraph.pmu.cpu", sample.cpu));
        span_attrs.push_back(
            make_span_bool("callgraph.pmu.approximate", true));
        emit_point(stack, sample.tid, user_depth, CG_KCAT_PMU,
                   "pmu." + name, sample.ts, std::move(span_attrs));
    }
}

void KernelTimeline::record_open_intervals(uint32_t tid, uint64_t ts,
                                           const CallStack& stack)
{
    if (!collect_histograms_)
        return;

    auto it = threads_.find(tid);
    if (it == threads_.end())
        return;

    ThreadRuntime& thread = it->second;
    if (thread.offcpu_since_ns != 0 && ts >= thread.offcpu_since_ns)
        record_kernel_histogram(tid, stack, "sched.off_cpu",
                                ts - thread.offcpu_since_ns, true);
    if (thread.runnable_since_ns != 0 && ts >= thread.runnable_since_ns)
        record_kernel_histogram(tid, stack, "sched.runqueue",
                                ts - thread.runnable_since_ns, true);
    for (const PendingOp& op : thread.ops) {
        if (ts >= op.ts)
            record_kernel_histogram(tid, stack, syscall_span_name(op.kind),
                                    ts - op.ts, true);
    }
    // Only the outermost reclaim interval is recorded when it closes, so do
    // the same for one still open at shutdown.  `reclaims` is populated only
    // when a span sink is attached, so it cannot be used here.
    if (thread.reclaim_depth != 0 && ts >= thread.reclaim_begin_ns)
        record_kernel_histogram(tid, stack, "direct_reclaim",
                                ts - thread.reclaim_begin_ns, true);
}

void KernelTimeline::account_until(uint32_t tid, uint64_t ts,
                                   const CallStack& stack)
{
    (void)stack;
    auto it = threads_.find(tid);
    if (it == threads_.end()) {
        ThreadRuntime runtime;
        runtime.last_ns = ts;
        runtime.have_last = true;
        threads_.emplace(tid, std::move(runtime));
        return;
    }

    ThreadRuntime& thread = it->second;
    if (!thread.have_last) {
        thread.last_ns = ts;
        thread.have_last = true;
        return;
    }
    if (ts <= thread.last_ns) {
        if (ts < thread.last_ns) {
            ++thread.out_of_order;
            ++out_of_order_;
        }
        return;
    }

    thread.last_ns = ts;
}

BlockReason KernelTimeline::classify_block(const ThreadRuntime& thread) const
{
    if (thread.reclaim_depth != 0)
        return BlockReason::Memory;
    for (auto it = thread.ops.rbegin(); it != thread.ops.rend(); ++it) {
        if (it->kind == CG_KEV_FUTEX_ENTER && futex_is_wait(it->op))
            return BlockReason::Futex;
        if (kernel_is_net_enter(it->kind))
            return BlockReason::Net;
        if (kernel_is_io_enter(it->kind))
            return BlockReason::Io;
    }
    if (thread.prev_state & 2)
        return BlockReason::Uninterruptible;
    if (thread.prev_state & 1)
        return BlockReason::Sleep;
    return BlockReason::Other;
}

std::string KernelTimeline::state_name(uint32_t state) const
{
    switch (state) {
    case 0:
        return "R";
    case 1:
        return "S";
    case 2:
        return "D";
    case 4:
        return "T";
    case 8:
        return "t";
    case 16:
        return "X";
    case 32:
        return "Z";
    case 64:
        return "P";
    case 128:
        return "I";
    default:
        return std::to_string(state);
    }
}

void KernelTimeline::emit_event(const KernelEvent& event, int depth,
                                const std::string& name,
                                const std::string& attrs)
{
    if (depth >= 0 && max_depth_ >= 0 && depth > max_depth_)
        return;
    output_.emit_kernel(event.ts, event.tid, depth,
                        kernel_category_name(event.category), name, attrs);
}

uint64_t KernelTimeline::function_span_token(const CallStack& stack,
                                             uint32_t tid) const
{
    const auto frames = stack.traced_frames_for(tid);
    if (frames.empty())
        return 0;
    return frames.back().span_token;
}

uint64_t KernelTimeline::innermost_span_token(uint32_t tid,
                                              const CallStack& stack) const
{
    const auto thread = threads_.find(tid);
    if (thread != threads_.end()) {
        const ThreadRuntime& runtime = thread->second;
        if (runtime.runqueue_span_token != 0)
            return runtime.runqueue_span_token;
        if (runtime.offcpu_span_token != 0)
            return runtime.offcpu_span_token;
        for (auto it = runtime.reclaims.rbegin();
             it != runtime.reclaims.rend(); ++it) {
            if (it->span_token != 0)
                return it->span_token;
        }
        for (auto it = runtime.ops.rbegin(); it != runtime.ops.rend(); ++it) {
            if (it->span_token != 0)
                return it->span_token;
        }
    }
    return function_span_token(stack, tid);
}

uint64_t KernelTimeline::open_span(const CallStack& stack, uint32_t tid,
                                   uint32_t user_depth, uint8_t category,
                                   const std::string& name, uint64_t ts,
                                   std::vector<SpanAttribute> attributes)
{
    if (!span_sink_)
        return 0;
    const uint64_t parent = innermost_span_token(tid, stack);
    if (parent == 0)
        return 0;

    KernelSpanStart start;
    start.parent_token = parent;
    start.tid = tid;
    start.user_depth = user_depth;
    start.category = category;
    start.name = name;
    start.ts = ts;
    start.attributes = std::move(attributes);
    return span_sink_->on_kernel_enter(std::move(start));
}

void KernelTimeline::close_span(uint64_t token, uint64_t ts,
                                std::vector<SpanAttribute> attributes,
                                bool incomplete)
{
    if (!span_sink_ || token == 0)
        return;
    KernelSpanEnd end;
    end.ts = ts;
    end.attributes = std::move(attributes);
    end.incomplete = incomplete;
    span_sink_->on_kernel_exit(token, std::move(end));
}

void KernelTimeline::emit_point(const CallStack& stack, uint32_t tid,
                                uint32_t user_depth, uint8_t category,
                                const std::string& name, uint64_t ts,
                                std::vector<SpanAttribute> attributes,
                                uint64_t parent_override)
{
    if (!span_sink_)
        return;
    KernelSpanPoint point;
    point.parent_token = parent_override != 0
                             ? parent_override
                             : innermost_span_token(tid, stack);
    point.tid = tid;
    point.user_depth = user_depth;
    point.category = category;
    point.name = name;
    point.ts = ts;
    point.attributes = std::move(attributes);
    span_sink_->on_kernel_point(std::move(point));
}

void KernelTimeline::on_function_event(const TraceEvent& event,
                                       const CallStack& stack)
{
    exited_.erase(event.tid);
    auto it = threads_.find(event.tid);
    if (it == threads_.end()) {
        ThreadRuntime runtime;
        runtime.last_ns = event.ts;
        runtime.have_last = true;
        runtime.partial = true;
        threads_.emplace(event.tid, std::move(runtime));
        return;
    }
    account_until(event.tid, event.ts, stack);
}

void KernelTimeline::on_sched_switch(const KernelEvent& event,
                                     const CallStack& stack)
{
    const uint32_t prev = event.tid;
    const uint32_t next = event.peer_tid;
    const bool prev_target = is_target(prev);
    const bool next_target = is_target(next);

    if (prev_target)
        account_until(prev, event.ts, stack);
    if (next_target)
        account_until(next, event.ts, stack);

    if (prev_target) {
        ThreadRuntime& thread = threads_[prev];

        // An unfinished interval means events were lost; close it as
        // incomplete before starting the next one.
        if (thread.runqueue_span_token != 0) {
            close_span(thread.runqueue_span_token, event.ts, {}, true);
            thread.runqueue_span_token = 0;
        }
        if (thread.offcpu_span_token != 0) {
            close_span(thread.offcpu_span_token, event.ts, {}, true);
            thread.offcpu_span_token = 0;
        }

        // Lost events can leave an interval open across another switch-out.
        // Record it as incomplete before starting the new interval.
        if (thread.offcpu_since_ns != 0 && event.ts >= thread.offcpu_since_ns)
            record_kernel_histogram(prev, stack, "sched.off_cpu",
                                    event.ts - thread.offcpu_since_ns, true);
        if (thread.runnable_since_ns != 0 &&
            event.ts >= thread.runnable_since_ns)
            record_kernel_histogram(prev, stack, "sched.runqueue",
                                    event.ts - thread.runnable_since_ns, true);

        if (thread.state == CpuState::Unknown) {
            thread.partial = true;
        }
        thread.prev_state = static_cast<uint32_t>(event.a);
        thread.offcpu_since_ns = event.ts;
        thread.pending_switch_id = next_id();
        if (event.a == 0) {
            thread.state = CpuState::Runnable;
            thread.runnable_since_ns = event.ts;
            thread.reason = BlockReason::None;
        } else {
            thread.state = CpuState::Blocked;
            thread.reason = classify_block(thread);
        }

        std::string attrs;
        append_attr(attrs, "id", thread.pending_switch_id);
        append_attr(attrs, "next", next);
        append_text_attr(attrs, "state",
                         state_name(static_cast<uint32_t>(event.a)));
        emit_event(event, depth_of(stack, prev), "switch_out", attrs);

        if (span_sink_) {
            const uint32_t user_depth = span_user_depth(stack, prev);
            std::vector<SpanAttribute> span_attrs;
            add_common_span_attrs(span_attrs, "off_cpu", user_depth);
            add_uint_attr(span_attrs, "id", thread.pending_switch_id);
            add_uint_attr(span_attrs, "next", next);
            add_string_attr(span_attrs, "state",
                            state_name(static_cast<uint32_t>(event.a)));
            add_string_attr(span_attrs, "reason",
                            block_reason_name(thread.reason));
            thread.offcpu_span_token =
                open_span(stack, prev, user_depth, CG_KCAT_SCHED,
                          "sched.off_cpu", event.ts, std::move(span_attrs));
            thread.offcpu_span_start_ns = event.ts;
            thread.offcpu_user_depth = user_depth;
        }
    }

    if (next_target) {
        ThreadRuntime& thread = threads_[next];
        const bool partial = thread.state == CpuState::Unknown;
        const uint64_t offcpu =
            thread.offcpu_since_ns && event.ts >= thread.offcpu_since_ns
                ? event.ts - thread.offcpu_since_ns
                : 0;
        const uint64_t runqueue =
            thread.runnable_since_ns && event.ts >= thread.runnable_since_ns
                ? event.ts - thread.runnable_since_ns
                : 0;
        const uint64_t id = thread.pending_switch_id
                                ? thread.pending_switch_id
                                : next_id();

        // Close the nested runqueue interval before its off-CPU parent.
        if (thread.runqueue_span_token != 0) {
            close_span(thread.runqueue_span_token, event.ts, {}, partial);
            thread.runqueue_span_token = 0;
        }
        if (thread.offcpu_span_token != 0) {
            close_span(thread.offcpu_span_token, event.ts, {}, partial);
            thread.offcpu_span_token = 0;
        }

        if (thread.offcpu_since_ns != 0 && event.ts >= thread.offcpu_since_ns)
            record_kernel_histogram(next, stack, "sched.off_cpu", offcpu,
                                    partial);
        if (thread.runnable_since_ns != 0 &&
            event.ts >= thread.runnable_since_ns)
            record_kernel_histogram(next, stack, "sched.runqueue", runqueue,
                                    partial);

        thread.partial = thread.partial || partial;
        thread.state = CpuState::OnCpu;
        thread.offcpu_since_ns = 0;
        thread.runnable_since_ns = 0;
        thread.pending_switch_id = 0;
        thread.reason = BlockReason::None;

        std::string attrs;
        append_attr(attrs, "id", id);
        append_attr(attrs, "prev", prev);
        append_attr(attrs, "offcpu_ns", offcpu);
        append_attr(attrs, "runqueue_ns", runqueue);
        if (partial)
            append_attr(attrs, "partial", 1);
        KernelEvent next_event = event;
        next_event.tid = next;
        next_event.tgid = event.peer_tgid;
        next_event.peer_tid = prev;
        next_event.peer_tgid = event.tgid;
        emit_event(next_event, depth_of(stack, next), "switch_in", attrs);
    }
}

void KernelTimeline::on_sched_wakeup(const KernelEvent& event,
                                     const CallStack& stack)
{
    const uint32_t target = event.tid;
    const uint32_t waker = event.peer_tid;

    if (is_target(target))
        account_until(target, event.ts, stack);
    if (waker != target && is_target(waker))
        account_until(waker, event.ts, stack);

    if (!is_target(target))
        return;

    ThreadRuntime& thread = threads_[target];
    if (thread.state == CpuState::OnCpu)
        return;

    if (thread.state == CpuState::Unknown) {
        thread.partial = true;
    }
    bool started_runnable = false;
    if (thread.state != CpuState::Runnable) {
        thread.state = CpuState::Runnable;
        thread.runnable_since_ns = event.ts;
        thread.reason = BlockReason::None;
        started_runnable = true;
    }
    if (thread.pending_switch_id == 0)
        thread.pending_switch_id = next_id();

    std::string attrs;
    append_attr(attrs, "id", thread.pending_switch_id);
    append_attr(attrs, "by", waker);
    append_attr(attrs, "cpu", event.c);
    append_attr(attrs, "prio", event.a);
    emit_event(event, depth_of(stack, target), kernel_kind_name(event.kind),
               attrs);

    if (collect_histograms_)
        record_kernel_histogram(
            target, stack,
            "sched." + std::string(kernel_kind_name(event.kind)), 0);

    if (span_sink_) {
        const uint32_t user_depth = span_user_depth(stack, target);
        const std::string event_name = kernel_kind_name(event.kind);
        std::vector<SpanAttribute> point_attrs;
        add_common_span_attrs(point_attrs, event_name.c_str(), user_depth);
        add_uint_attr(point_attrs, "id", thread.pending_switch_id);
        add_uint_attr(point_attrs, "by", waker);
        add_uint_attr(point_attrs, "cpu", event.c);
        add_uint_attr(point_attrs, "prio", event.a);
        emit_point(stack, target, user_depth, CG_KCAT_SCHED,
                   "sched." + event_name, event.ts, std::move(point_attrs));

        if (started_runnable) {
            std::vector<SpanAttribute> span_attrs;
            add_common_span_attrs(span_attrs, "runqueue", user_depth);
            add_uint_attr(span_attrs, "id", thread.pending_switch_id);
            add_uint_attr(span_attrs, "by", waker);
            add_uint_attr(span_attrs, "cpu", event.c);
            add_uint_attr(span_attrs, "prio", event.a);
            thread.runqueue_span_token =
                open_span(stack, target, user_depth, CG_KCAT_SCHED,
                          "sched.runqueue", event.ts, std::move(span_attrs));
            thread.runqueue_span_start_ns = event.ts;
            thread.runqueue_user_depth = user_depth;
        }
    }
}

void KernelTimeline::on_futex(const KernelEvent& event, const CallStack& stack)
{
    account_until(event.tid, event.ts, stack);
    ThreadRuntime& thread = threads_[event.tid];

    if (event.kind == CG_KEV_FUTEX_ENTER) {
        PendingOp op;
        op.kind = event.kind;
        op.ts = event.ts;
        op.id = next_id();
        op.nr = static_cast<uint32_t>(event.a);
        op.op = static_cast<uint32_t>(event.c);
        op.user_depth = span_user_depth(stack, event.tid);
        thread.ops.push_back(op);

        std::string attrs;
        append_attr(attrs, "id", op.id);
        append_hex_attr(attrs, "uaddr", event.b);
        append_hex_attr(attrs, "op", op.op);
        append_attr(attrs, "val", event.d);
        const char* name = futex_is_wait(op.op)
                               ? "wait_begin"
                               : futex_is_wake(op.op) ? "wake" : "futex_begin";
        emit_event(event, depth_of(stack, event.tid), name, attrs);

        if (span_sink_) {
            std::vector<SpanAttribute> span_attrs;
            add_common_span_attrs(span_attrs, "futex", op.user_depth);
            add_uint_attr(span_attrs, "id", op.id);
            add_uint_attr(span_attrs, "nr", event.a);
            add_string_attr(span_attrs, "operation",
                            futex_is_wait(op.op)
                                ? "wait"
                                : futex_is_wake(op.op) ? "wake" : "other");
            for (const ArgSpec& spec : enter_arg_specs(event.kind))
                add_arg_attr(span_attrs, spec, event);
            thread.ops.back().span_token =
                open_span(stack, event.tid, op.user_depth, CG_KCAT_FUTEX,
                          "@futex", event.ts, std::move(span_attrs));
        }
        return;
    }

    PendingOp pending;
    bool found = false;
    for (auto it = thread.ops.rbegin(); it != thread.ops.rend(); ++it) {
        if (it->kind == CG_KEV_FUTEX_ENTER) {
            pending = *it;
            thread.ops.erase(std::next(it).base());
            found = true;
            break;
        }
    }
    if (!found) {
        std::string attrs;
        append_signed_attr(attrs, "ret", static_cast<int64_t>(event.b));
        attrs += " unmatched=1";
        emit_event(event, depth_of(stack, event.tid), "futex_end", attrs);

        if (collect_histograms_)
            record_kernel_histogram(event.tid, stack,
                                    syscall_span_name(CG_KEV_FUTEX_ENTER), 0,
                                    true);

        if (span_sink_) {
            const uint32_t user_depth = span_user_depth(stack, event.tid);
            std::vector<SpanAttribute> span_attrs;
            add_common_span_attrs(span_attrs, "futex", user_depth);
            add_uint_attr(span_attrs, "nr", event.a);
            add_int_attr(span_attrs, "ret", static_cast<int64_t>(event.b));
            add_bool_attr(span_attrs, "unmatched", true);
            add_bool_attr(span_attrs, "incomplete", true);
            emit_point(stack, event.tid, user_depth, CG_KCAT_FUTEX, "@futex",
                       event.ts, std::move(span_attrs),
                       function_span_token(stack, event.tid));
        }
        return;
    }

    std::string attrs;
    append_attr(attrs, "id", pending.id);
    append_signed_attr(attrs, "ret", static_cast<int64_t>(event.b));
    if (event.ts >= pending.ts)
        append_attr(attrs, "duration_ns", event.ts - pending.ts);
    const char* name = futex_is_wait(pending.op)
                           ? "wait_end"
                           : futex_is_wake(pending.op) ? "wake_end"
                                                       : "futex_end";
    emit_event(event, depth_of(stack, event.tid), name, attrs);

    if (collect_histograms_ && event.ts >= pending.ts)
        record_kernel_histogram(event.tid, stack,
                                syscall_span_name(CG_KEV_FUTEX_ENTER),
                                event.ts - pending.ts);

    if (span_sink_) {
        std::vector<SpanAttribute> end_attrs;
        add_int_attr(end_attrs, "ret", static_cast<int64_t>(event.b));
        close_span(pending.span_token, event.ts, std::move(end_attrs), false);
    }
}

void KernelTimeline::on_io(const KernelEvent& event, const CallStack& stack)
{
    account_until(event.tid, event.ts, stack);
    ThreadRuntime& thread = threads_[event.tid];

    if (kernel_is_io_enter(event.kind)) {
        PendingOp op;
        op.kind = event.kind;
        op.ts = event.ts;
        op.id = next_id();
        op.fd = event.b;
        op.nr = static_cast<uint32_t>(event.a);
        op.user_depth = span_user_depth(stack, event.tid);
        thread.ops.push_back(op);

        std::string attrs;
        append_attr(attrs, "id", op.id);
        if (event.kind == CG_KEV_OPENAT_ENTER) {
            append_signed_attr(attrs, "dfd",
                               static_cast<int32_t>(event.b));
            append_hex_attr(attrs, "flags", event.d);
        } else {
            append_signed_attr(attrs, "fd", static_cast<int32_t>(event.b));
            if (event.kind == CG_KEV_READ_ENTER ||
                event.kind == CG_KEV_WRITE_ENTER ||
                event.kind == CG_KEV_PREAD64_ENTER ||
                event.kind == CG_KEV_PWRITE64_ENTER)
                append_attr(attrs, "count", event.d);
        }
        emit_event(event, depth_of(stack, event.tid),
                   kernel_io_event_name(event.kind), attrs);

        if (span_sink_) {
            std::vector<SpanAttribute> span_attrs;
            add_common_span_attrs(span_attrs,
                                  syscall_name(event.kind).c_str(),
                                  op.user_depth);
            add_uint_attr(span_attrs, "id", op.id);
            add_uint_attr(span_attrs, "nr", event.a);
            for (const ArgSpec& spec : enter_arg_specs(event.kind))
                add_arg_attr(span_attrs, spec, event);
            thread.ops.back().span_token =
                open_span(stack, event.tid, op.user_depth, CG_KCAT_IO,
                          syscall_span_name(event.kind), event.ts,
                          std::move(span_attrs));
        }
        return;
    }

    const uint16_t enter_kind = static_cast<uint16_t>(event.kind - 1);
    PendingOp pending;
    bool found = false;
    for (auto it = thread.ops.rbegin(); it != thread.ops.rend(); ++it) {
        if (it->kind == enter_kind) {
            pending = *it;
            thread.ops.erase(std::next(it).base());
            found = true;
            break;
        }
    }
    if (!found) {
        std::string attrs;
        append_signed_attr(attrs, "ret", static_cast<int64_t>(event.b));
        attrs += " unmatched=1";
        emit_event(event, depth_of(stack, event.tid),
                   kernel_io_event_name(event.kind), attrs);

        if (collect_histograms_)
            record_kernel_histogram(event.tid, stack,
                                    syscall_span_name(enter_kind), 0, true);

        if (span_sink_) {
            const uint32_t user_depth = span_user_depth(stack, event.tid);
            std::vector<SpanAttribute> span_attrs;
            add_common_span_attrs(span_attrs,
                                  syscall_name(enter_kind).c_str(),
                                  user_depth);
            add_uint_attr(span_attrs, "nr", event.a);
            add_int_attr(span_attrs, "ret", static_cast<int64_t>(event.b));
            add_bool_attr(span_attrs, "unmatched", true);
            add_bool_attr(span_attrs, "incomplete", true);
            emit_point(stack, event.tid, user_depth, CG_KCAT_IO,
                       syscall_span_name(enter_kind), event.ts,
                       std::move(span_attrs),
                       function_span_token(stack, event.tid));
        }
        return;
    }

    std::string attrs;
    append_attr(attrs, "id", pending.id);
    append_signed_attr(attrs, "ret", static_cast<int64_t>(event.b));
    if (event.ts >= pending.ts)
        append_attr(attrs, "duration_ns", event.ts - pending.ts);
    emit_event(event, depth_of(stack, event.tid),
               kernel_io_event_name(event.kind), attrs);

    if (collect_histograms_ && event.ts >= pending.ts)
        record_kernel_histogram(event.tid, stack,
                                syscall_span_name(enter_kind),
                                event.ts - pending.ts);

    if (span_sink_) {
        std::vector<SpanAttribute> end_attrs;
        add_int_attr(end_attrs, "ret", static_cast<int64_t>(event.b));
        close_span(pending.span_token, event.ts, std::move(end_attrs), false);
    }
}

void KernelTimeline::on_net(const KernelEvent& event, const CallStack& stack)
{
    account_until(event.tid, event.ts, stack);
    ThreadRuntime& thread = threads_[event.tid];

    if (kernel_is_net_enter(event.kind)) {
        PendingOp op;
        op.kind = event.kind;
        op.ts = event.ts;
        op.id = next_id();
        op.fd = event.b;
        op.nr = static_cast<uint32_t>(event.a);
        op.user_depth = span_user_depth(stack, event.tid);
        thread.ops.push_back(op);

        std::string attrs;
        append_attr(attrs, "id", op.id);
        switch (event.kind) {
        case CG_KEV_NET_SOCKET_ENTER:
            append_attr(attrs, "family", event.b);
            append_attr(attrs, "type", event.c);
            append_attr(attrs, "protocol", event.d);
            break;
        case CG_KEV_NET_CONNECT_ENTER:
            append_signed_attr(attrs, "fd", static_cast<int32_t>(event.b));
            append_hex_attr(attrs, "addr", event.c);
            append_signed_attr(attrs, "addrlen",
                               static_cast<int32_t>(event.d));
            break;
        case CG_KEV_NET_ACCEPT4_ENTER:
            append_signed_attr(attrs, "fd", static_cast<int32_t>(event.b));
            append_hex_attr(attrs, "addr", event.c);
            append_hex_attr(attrs, "addrlen", event.d);
            append_attr(attrs, "flags", event.e);
            break;
        case CG_KEV_NET_SENDTO_ENTER:
            append_signed_attr(attrs, "fd", static_cast<int32_t>(event.b));
            append_attr(attrs, "len", event.d);
            append_attr(attrs, "flags", event.e);
            append_hex_attr(attrs, "addr", event.f);
            append_signed_attr(attrs, "addr_len",
                               static_cast<int32_t>(event.g));
            break;
        case CG_KEV_NET_RECVFROM_ENTER:
            append_signed_attr(attrs, "fd", static_cast<int32_t>(event.b));
            append_attr(attrs, "size", event.d);
            append_attr(attrs, "flags", event.e);
            append_hex_attr(attrs, "addr", event.f);
            append_hex_attr(attrs, "addr_len", event.g);
            break;
        case CG_KEV_NET_SENDMSG_ENTER:
        case CG_KEV_NET_RECVMSG_ENTER:
            append_signed_attr(attrs, "fd", static_cast<int32_t>(event.b));
            append_hex_attr(attrs, "msg", event.c);
            append_attr(attrs, "flags", event.d);
            break;
        case CG_KEV_NET_EPOLL_WAIT_ENTER:
            append_signed_attr(attrs, "epfd", static_cast<int32_t>(event.b));
            append_hex_attr(attrs, "events", event.c);
            append_attr(attrs, "maxevents", event.d);
            append_signed_attr(attrs, "timeout",
                               static_cast<int32_t>(event.e));
            break;
        case CG_KEV_NET_POLL_ENTER:
            append_hex_attr(attrs, "fds", event.b);
            append_attr(attrs, "nfds", event.c);
            append_signed_attr(attrs, "timeout",
                               static_cast<int32_t>(event.d));
            break;
        default:
            break;
        }
        emit_event(event, depth_of(stack, event.tid),
                   kernel_net_event_name(event.kind), attrs);

        if (span_sink_) {
            std::vector<SpanAttribute> span_attrs;
            add_common_span_attrs(span_attrs,
                                  syscall_name(event.kind).c_str(),
                                  op.user_depth);
            add_uint_attr(span_attrs, "id", op.id);
            add_uint_attr(span_attrs, "nr", event.a);
            for (const ArgSpec& spec : enter_arg_specs(event.kind))
                add_arg_attr(span_attrs, spec, event);
            thread.ops.back().span_token =
                open_span(stack, event.tid, op.user_depth, CG_KCAT_NET,
                          syscall_span_name(event.kind), event.ts,
                          std::move(span_attrs));
        }
        return;
    }

    const uint16_t enter_kind = static_cast<uint16_t>(event.kind - 1);
    PendingOp pending;
    bool found = false;
    for (auto it = thread.ops.rbegin(); it != thread.ops.rend(); ++it) {
        if (it->kind == enter_kind) {
            pending = *it;
            thread.ops.erase(std::next(it).base());
            found = true;
            break;
        }
    }

    std::string attrs;
    if (!found) {
        append_signed_attr(attrs, "ret", static_cast<int64_t>(event.b));
        attrs += " unmatched=1";
    } else {
        append_attr(attrs, "id", pending.id);
        append_signed_attr(attrs, "ret", static_cast<int64_t>(event.b));
        if (event.ts >= pending.ts)
            append_attr(attrs, "duration_ns", event.ts - pending.ts);
    }
    emit_event(event, depth_of(stack, event.tid),
               kernel_net_event_name(event.kind), attrs);

    if (collect_histograms_) {
        if (!found)
            record_kernel_histogram(event.tid, stack,
                                    syscall_span_name(enter_kind), 0, true);
        else if (event.ts >= pending.ts)
            record_kernel_histogram(event.tid, stack,
                                    syscall_span_name(enter_kind),
                                    event.ts - pending.ts);
    }

    if (span_sink_) {
        if (!found) {
            const uint32_t user_depth = span_user_depth(stack, event.tid);
            std::vector<SpanAttribute> span_attrs;
            add_common_span_attrs(span_attrs,
                                  syscall_name(enter_kind).c_str(),
                                  user_depth);
            add_uint_attr(span_attrs, "nr", event.a);
            add_int_attr(span_attrs, "ret", static_cast<int64_t>(event.b));
            add_bool_attr(span_attrs, "unmatched", true);
            add_bool_attr(span_attrs, "incomplete", true);
            emit_point(stack, event.tid, user_depth, CG_KCAT_NET,
                       syscall_span_name(enter_kind), event.ts,
                       std::move(span_attrs),
                       function_span_token(stack, event.tid));
        } else {
            std::vector<SpanAttribute> end_attrs;
            add_int_attr(end_attrs, "ret", static_cast<int64_t>(event.b));
            close_span(pending.span_token, event.ts, std::move(end_attrs),
                       false);
        }
    }
}

void KernelTimeline::on_mm(const KernelEvent& event, const CallStack& stack)
{
    account_until(event.tid, event.ts, stack);
    ThreadRuntime& thread = threads_[event.tid];

    if (event.kind == CG_KEV_PAGE_FAULT_USER ||
        event.kind == CG_KEV_PAGE_FAULT_KERNEL) {
        const int depth = depth_of(stack, event.tid);

        std::string attrs;
        append_text_attr(attrs, "space",
                         event.kind == CG_KEV_PAGE_FAULT_USER ? "user"
                                                             : "kernel");
        append_hex_attr(attrs, "address", event.a);
        append_hex_attr(attrs, "ip", event.b);
        append_hex_attr(attrs, "error", event.c);
        emit_event(event, depth, "page_fault", attrs);

        if (collect_histograms_)
            record_kernel_histogram(
                event.tid, stack,
                event.kind == CG_KEV_PAGE_FAULT_USER ? "page_fault.user"
                                                     : "page_fault.kernel",
                0);

        if (span_sink_) {
            const uint32_t user_depth = span_user_depth(stack, event.tid);
            std::vector<SpanAttribute> span_attrs;
            add_common_span_attrs(span_attrs, "page_fault", user_depth);
            add_string_attr(span_attrs, "space",
                            event.kind == CG_KEV_PAGE_FAULT_USER ? "user"
                                                                : "kernel");
            add_hex_attr(span_attrs, "address", event.a);
            add_hex_attr(span_attrs, "ip", event.b);
            add_hex_attr(span_attrs, "error", event.c);
            emit_point(stack, event.tid, user_depth, CG_KCAT_MM,
                       event.kind == CG_KEV_PAGE_FAULT_USER
                           ? "page_fault.user"
                           : "page_fault.kernel",
                       event.ts, std::move(span_attrs));
        }
        return;
    }

    if (event.kind == CG_KEV_DIRECT_RECLAIM_BEGIN) {
        if (thread.reclaim_depth == 0) {
            thread.reclaim_begin_ns = event.ts;
            thread.reclaim_id = next_id();
        }
        thread.reclaim_depth += 1;

        std::string attrs;
        append_attr(attrs, "id", thread.reclaim_id);
        append_signed_attr(attrs, "order", static_cast<int32_t>(event.a));
        append_hex_attr(attrs, "gfp", event.b);
        emit_event(event, depth_of(stack, event.tid),
                   "direct_reclaim_begin", attrs);

        if (span_sink_) {
            const uint32_t user_depth = span_user_depth(stack, event.tid);
            ReclaimInterval interval;
            interval.begin_ts = event.ts;
            interval.id = next_id();
            interval.order = event.a;
            interval.gfp = event.b;
            interval.user_depth = user_depth;
            std::vector<SpanAttribute> span_attrs;
            add_common_span_attrs(span_attrs, "direct_reclaim", user_depth);
            add_uint_attr(span_attrs, "id", interval.id);
            add_int_attr(span_attrs, "order", static_cast<int32_t>(event.a));
            add_hex_attr(span_attrs, "gfp", event.b);
            interval.span_token =
                open_span(stack, event.tid, user_depth, CG_KCAT_MM,
                          "direct_reclaim", event.ts, std::move(span_attrs));
            thread.reclaims.push_back(interval);
        }
        return;
    }

    const bool matched = thread.reclaim_depth != 0;
    std::string attrs;
    if (matched) {
        thread.reclaim_depth -= 1;
        append_attr(attrs, "id", thread.reclaim_id);
        append_attr(attrs, "nr_reclaimed", event.a);
        if (thread.reclaim_depth == 0 &&
            event.ts >= thread.reclaim_begin_ns)
            append_attr(attrs, "duration_ns",
                        event.ts - thread.reclaim_begin_ns);
    } else {
        append_attr(attrs, "unmatched", 1);
        append_attr(attrs, "nr_reclaimed", event.a);
    }
    emit_event(event, depth_of(stack, event.tid), "direct_reclaim_end", attrs);

    if (collect_histograms_) {
        if (matched) {
            if (thread.reclaim_depth == 0 &&
                event.ts >= thread.reclaim_begin_ns)
                record_kernel_histogram(event.tid, stack, "direct_reclaim",
                                        event.ts - thread.reclaim_begin_ns);
        } else {
            record_kernel_histogram(event.tid, stack, "direct_reclaim", 0,
                                    true);
        }
    }

    if (span_sink_) {
        if (matched && !thread.reclaims.empty()) {
            ReclaimInterval interval = thread.reclaims.back();
            thread.reclaims.pop_back();
            std::vector<SpanAttribute> end_attrs;
            add_uint_attr(end_attrs, "nr_reclaimed", event.a);
            close_span(interval.span_token, event.ts, std::move(end_attrs),
                       false);
        } else if (!matched) {
            const uint32_t user_depth = span_user_depth(stack, event.tid);
            std::vector<SpanAttribute> span_attrs;
            add_common_span_attrs(span_attrs, "direct_reclaim", user_depth);
            add_uint_attr(span_attrs, "nr_reclaimed", event.a);
            add_bool_attr(span_attrs, "unmatched", true);
            add_bool_attr(span_attrs, "incomplete", true);
            emit_point(stack, event.tid, user_depth, CG_KCAT_MM,
                       "direct_reclaim", event.ts, std::move(span_attrs),
                       function_span_token(stack, event.tid));
        }
    }
}

void KernelTimeline::on_tcp_retransmit(const KernelEvent& event)
{
    std::string attrs;
    append_attr(attrs, "state", event.a);
    append_attr(attrs, "sport", event.b);
    append_attr(attrs, "dport", event.c);
    append_attr(attrs, "family", event.d);
    if (event.d == 2) {
        append_text_attr(attrs, "saddr", ipv4_text(event.e));
        append_text_attr(attrs, "daddr", ipv4_text(event.f));
    }
    if (event.g != 0)
        append_signed_attr(attrs, "err", static_cast<int64_t>(event.g));
    emit_event(event, kKernelDepthGlobal, "tcp_retransmit", attrs);
}

void KernelTimeline::on_block(const KernelEvent& event)
{
    const BlockKey key{static_cast<uint32_t>(event.a), event.b,
                       static_cast<uint32_t>(event.c)};
    std::string attrs;
    append_text_attr(attrs, "dev", device_text(event.a));
    append_attr(attrs, "sector", event.b);
    append_attr(attrs, "nr_sector", event.c);

    if (event.kind == CG_KEV_BLOCK_INSERT) {
        BlockPending pending;
        pending.insert_ns = event.ts;
        pending.id = next_id();
        block_pending_[key] = pending;
        append_attr(attrs, "id", pending.id);
        if (event.d != 0)
            append_attr(attrs, "bytes", event.d);
        emit_event(event, kKernelDepthGlobal, "rq_insert", attrs);
        return;
    }

    const auto it = block_pending_.find(key);
    if (it == block_pending_.end()) {
        if (event.kind == CG_KEV_BLOCK_ISSUE) {
            BlockPending pending;
            pending.insert_ns = event.ts;
            pending.issue_ns = event.ts;
            pending.issued = true;
            pending.id = next_id();
            block_pending_[key] = pending;
            append_attr(attrs, "id", pending.id);
            append_attr(attrs, "insert_missing", 1);
            if (event.d != 0)
                append_attr(attrs, "bytes", event.d);
            emit_event(event, kKernelDepthGlobal, "rq_issue", attrs);
            return;
        }
        append_attr(attrs, "id", next_id());
        append_attr(attrs, "unmatched", 1);
        if (event.e != 0)
            append_attr(attrs, "error", event.e);
        emit_event(event, kKernelDepthGlobal,
                   kernel_kind_name(event.kind), attrs);
        return;
    }

    BlockPending& pending = it->second;
    append_attr(attrs, "id", pending.id);
    if (event.kind == CG_KEV_BLOCK_ISSUE) {
        pending.issue_ns = event.ts;
        pending.issued = true;
        if (event.d != 0)
            append_attr(attrs, "bytes", event.d);
        if (event.ts >= pending.insert_ns)
            append_attr(attrs, "queue_ns", event.ts - pending.insert_ns);
        emit_event(event, kKernelDepthGlobal, "rq_issue", attrs);
        return;
    }

    if (event.kind == CG_KEV_BLOCK_COMPLETE) {
        if (pending.issued && event.ts >= pending.issue_ns)
            append_attr(attrs, "device_ns", event.ts - pending.issue_ns);
        if (event.ts >= pending.insert_ns)
            append_attr(attrs, "total_ns", event.ts - pending.insert_ns);
        if (event.e != 0)
            append_attr(attrs, "error", event.e);
        emit_event(event, kKernelDepthGlobal, "rq_complete", attrs);
        block_pending_.erase(it);
        return;
    }

    if (event.e != 0)
        append_attr(attrs, "error", event.e);
    emit_event(event, kKernelDepthGlobal, kernel_kind_name(event.kind), attrs);
    if (event.kind == CG_KEV_BLOCK_ERROR)
        block_pending_.erase(it);
}

void KernelTimeline::on_kernel_event(const KernelEvent& event,
                                     const CallStack& stack)
{
    if (exited_.count(event.tid) != 0 &&
        event.kind != CG_KEV_PROC_EXIT)
        return;
    ++kernel_events_;
    switch (event.kind) {
    case CG_KEV_SCHED_SWITCH:
        on_sched_switch(event, stack);
        break;
    case CG_KEV_SCHED_WAKEUP:
    case CG_KEV_SCHED_WAKING:
    case CG_KEV_SCHED_WAKEUP_NEW:
        on_sched_wakeup(event, stack);
        break;
    case CG_KEV_SCHED_MIGRATE:
        if (is_target(event.tid)) {
            account_until(event.tid, event.ts, stack);
            std::string attrs;
            append_attr(attrs, "orig_cpu", event.b);
            append_attr(attrs, "dest_cpu", event.c);
            append_attr(attrs, "prio", event.a);
            emit_event(event, depth_of(stack, event.tid), "migrate", attrs);

            if (collect_histograms_)
                record_kernel_histogram(event.tid, stack, "sched.migrate", 0);

            if (span_sink_) {
                const uint32_t user_depth = span_user_depth(stack, event.tid);
                std::vector<SpanAttribute> span_attrs;
                add_common_span_attrs(span_attrs, "migrate", user_depth);
                add_uint_attr(span_attrs, "orig_cpu", event.b);
                add_uint_attr(span_attrs, "dest_cpu", event.c);
                add_uint_attr(span_attrs, "prio", event.a);
                emit_point(stack, event.tid, user_depth, CG_KCAT_SCHED,
                           "sched.migrate", event.ts, std::move(span_attrs));
            }
        }
        break;
    case CG_KEV_PROC_FORK:
        if (is_target(event.tid)) {
            account_until(event.tid, event.ts, stack);
            std::string attrs;
            append_attr(attrs, "child", event.peer_tid);
            emit_event(event, depth_of(stack, event.tid), "fork", attrs);

            if (collect_histograms_)
                record_kernel_histogram(event.tid, stack, "proc.fork", 0);

            if (span_sink_) {
                const uint32_t user_depth = span_user_depth(stack, event.tid);
                std::vector<SpanAttribute> span_attrs;
                add_common_span_attrs(span_attrs, "fork", user_depth);
                add_uint_attr(span_attrs, "child", event.peer_tid);
                emit_point(stack, event.tid, user_depth, CG_KCAT_SCHED,
                           "proc.fork", event.ts, std::move(span_attrs));
            }
        }
        break;
    case CG_KEV_PROC_EXIT:
        if (is_target(event.tid)) {
            account_until(event.tid, event.ts, stack);
            std::string attrs;
            append_attr(attrs, "prio", event.a);
            emit_event(event, depth_of(stack, event.tid), "exit", attrs);

            if (collect_histograms_) {
                record_kernel_histogram(event.tid, stack, "proc.exit", 0);
                record_open_intervals(event.tid, event.ts, stack);
            }

            if (span_sink_) {
                const uint32_t user_depth = span_user_depth(stack, event.tid);
                std::vector<SpanAttribute> span_attrs;
                add_common_span_attrs(span_attrs, "exit", user_depth);
                add_uint_attr(span_attrs, "prio", event.a);
                emit_point(stack, event.tid, user_depth, CG_KCAT_SCHED,
                           "proc.exit", event.ts, std::move(span_attrs));

                auto thread = threads_.find(event.tid);
                if (thread != threads_.end()) {
                    ThreadRuntime& runtime = thread->second;
                    if (runtime.runqueue_span_token != 0) {
                        close_span(runtime.runqueue_span_token, event.ts, {},
                                   true);
                    }
                    if (runtime.offcpu_span_token != 0)
                        close_span(runtime.offcpu_span_token, event.ts, {},
                                   true);
                    for (auto it = runtime.reclaims.rbegin();
                         it != runtime.reclaims.rend(); ++it)
                        close_span(it->span_token, event.ts, {}, true);
                    for (auto it = runtime.ops.rbegin();
                         it != runtime.ops.rend(); ++it)
                        close_span(it->span_token, event.ts, {}, true);
                }
            }
            exited_.insert(event.tid);
            threads_.erase(event.tid);
        }
        break;
    case CG_KEV_FUTEX_ENTER:
    case CG_KEV_FUTEX_EXIT:
        if (is_target(event.tid))
            on_futex(event, stack);
        break;
    case CG_KEV_BLOCK_INSERT:
    case CG_KEV_BLOCK_ISSUE:
    case CG_KEV_BLOCK_COMPLETE:
    case CG_KEV_BLOCK_REQUEUE:
    case CG_KEV_BLOCK_ERROR:
        on_block(event);
        break;
    case CG_KEV_PAGE_FAULT_USER:
    case CG_KEV_PAGE_FAULT_KERNEL:
    case CG_KEV_DIRECT_RECLAIM_BEGIN:
    case CG_KEV_DIRECT_RECLAIM_END:
        if (is_target(event.tid))
            on_mm(event, stack);
        break;
    case CG_KEV_TCP_RETRANSMIT:
        on_tcp_retransmit(event);
        break;
    default:
        if (kernel_is_net_enter(event.kind) ||
            kernel_is_net_exit(event.kind)) {
            if (is_target(event.tid))
                on_net(event, stack);
        } else if (kernel_is_io_enter(event.kind) ||
                   kernel_is_io_exit(event.kind)) {
            if (is_target(event.tid))
                on_io(event, stack);
        }
        break;
    }
}

void KernelTimeline::finish(uint64_t stop_ts, const CallStack& stack)
{
    std::vector<uint32_t> tids;
    tids.reserve(threads_.size());
    for (const auto& [tid, thread] : threads_) {
        (void)thread;
        tids.push_back(tid);
    }
    for (uint32_t tid : tids) {
        account_until(tid, stop_ts, stack);
        record_open_intervals(tid, stop_ts, stack);
        auto& thread = threads_[tid];
        if (thread.runqueue_span_token != 0) {
            close_span(thread.runqueue_span_token, stop_ts, {}, true);
            thread.runqueue_span_token = 0;
        }
        if (thread.offcpu_span_token != 0) {
            close_span(thread.offcpu_span_token, stop_ts, {}, true);
            thread.offcpu_span_token = 0;
        }
        for (auto it = thread.reclaims.rbegin(); it != thread.reclaims.rend();
             ++it) {
            close_span(it->span_token, stop_ts, {}, true);
            it->span_token = 0;
        }
        for (auto it = thread.ops.rbegin(); it != thread.ops.rend(); ++it) {
            close_span(it->span_token, stop_ts, {}, true);
            it->span_token = 0;
        }
        if (!thread.ops.empty() || thread.reclaim_depth != 0)
            thread.partial = true;
    }
}

}  // namespace callgraph
