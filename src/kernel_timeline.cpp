#include "callgraph/kernel_timeline.h"

#include <algorithm>
#include <cinttypes>
#include <cstdio>
#include <iterator>
#include <limits>
#include <sstream>
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

std::string format_ns(uint64_t ns)
{
    char buffer[64];
    if (ns >= 1000000000ULL)
        snprintf(buffer, sizeof(buffer), "%.3fs",
                 static_cast<double>(ns) / 1e9);
    else if (ns >= 1000000ULL)
        snprintf(buffer, sizeof(buffer), "%.3fms",
                 static_cast<double>(ns) / 1e6);
    else if (ns >= 1000ULL)
        snprintf(buffer, sizeof(buffer), "%.3fus",
                 static_cast<double>(ns) / 1e3);
    else
        snprintf(buffer, sizeof(buffer), "%" PRIu64 "ns", ns);
    return buffer;
}

int depth_of(const CallStack& stack, uint32_t tid)
{
    const auto* frames = stack.frames_for(tid);
    if (!frames || frames->empty())
        return kKernelDepthNone;
    return static_cast<int>(frames->size() - 1);
}

uint64_t function_of(const CallStack& stack, uint32_t tid)
{
    const auto* frames = stack.frames_for(tid);
    if (!frames || frames->empty())
        return 0;
    return frames->back().function_id;
}

std::string device_text(uint64_t value)
{
    const uint32_t dev = static_cast<uint32_t>(value);
    const uint32_t major = dev >> 20;
    const uint32_t minor = dev & ((1U << 20) - 1);
    return std::to_string(major) + ":" + std::to_string(minor);
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

uint64_t KernelCounters::blocked_total() const
{
    uint64_t total = 0;
    for (uint64_t value : blocked_ns)
        total += value;
    return total;
}

size_t KernelTimeline::StatKeyHash::operator()(const StatKey& key) const noexcept
{
    uint64_t hash = key.tid * 0x9e3779b97f4a7c15ULL;
    hash ^= key.depth + 0x9e3779b97f4a7c15ULL + (hash << 6) + (hash >> 2);
    hash ^= key.function_id + 0x9e3779b97f4a7c15ULL + (hash << 6) +
            (hash >> 2);
    return static_cast<size_t>(hash);
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

void KernelTimeline::add_account(uint32_t tid, uint32_t depth,
                                 uint64_t function_id, uint64_t delta_ns)
{
    auto& thread = threads_[tid];
    auto& total = thread_counters_[tid];
    total.kernel_events += 1;

    if (function_id != std::numeric_limits<uint64_t>::max()) {
        auto& function = function_counters_[StatKey{tid, depth, function_id}];
        function.kernel_events += 1;
        switch (thread.state) {
        case CpuState::OnCpu:
            function.cpu_ns += delta_ns;
            break;
        case CpuState::Runnable:
            function.runnable_ns += delta_ns;
            break;
        case CpuState::Blocked: {
            const size_t reason = static_cast<size_t>(thread.reason);
            function.blocked_ns[reason] += delta_ns;
            break;
        }
        case CpuState::Unknown:
            break;
        }
    }

    switch (thread.state) {
    case CpuState::OnCpu:
        total.cpu_ns += delta_ns;
        break;
    case CpuState::Runnable:
        total.runnable_ns += delta_ns;
        break;
    case CpuState::Blocked: {
        const size_t reason = static_cast<size_t>(thread.reason);
        total.blocked_ns[reason] += delta_ns;
        break;
    }
    case CpuState::Unknown:
        break;
    }
}

void KernelTimeline::account_until(uint32_t tid, uint64_t ts,
                                   const CallStack& stack)
{
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

    const uint64_t delta = ts - thread.last_ns;
    const int depth = depth_of(stack, tid);
    const uint32_t depth_key = depth < 0 ? 0 : static_cast<uint32_t>(depth);
    const uint64_t function_id =
        depth < 0 ? std::numeric_limits<uint64_t>::max() : function_of(stack, tid);
    add_account(tid, depth_key, function_id, delta);
    thread.last_ns = ts;
}

BlockReason KernelTimeline::classify_block(const ThreadRuntime& thread) const
{
    for (auto it = thread.ops.rbegin(); it != thread.ops.rend(); ++it) {
        if (it->kind == CG_KEV_FUTEX_ENTER && futex_is_wait(it->op))
            return BlockReason::Futex;
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
        thread_counters_[event.tid].partial = true;
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
        thread_counters_[prev].switches += 1;
        if (thread.state == CpuState::Unknown) {
            thread.partial = true;
            thread_counters_[prev].partial = true;
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
        thread.partial = thread.partial || partial;
        if (partial)
            thread_counters_[next].partial = true;
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
        thread_counters_[target].partial = true;
    }
    if (thread.state != CpuState::Runnable) {
        thread.state = CpuState::Runnable;
        thread.runnable_since_ns = event.ts;
        thread.reason = BlockReason::None;
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
        return;
    }

    std::string attrs;
    append_attr(attrs, "id", pending.id);
    append_signed_attr(attrs, "ret", static_cast<int64_t>(event.b));
    if (event.ts >= pending.ts)
        append_attr(attrs, "duration_ns", event.ts - pending.ts);
    emit_event(event, depth_of(stack, event.tid),
               kernel_io_event_name(event.kind), attrs);
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
            thread_counters_[event.tid].migrations += 1;
            std::string attrs;
            append_attr(attrs, "orig_cpu", event.b);
            append_attr(attrs, "dest_cpu", event.c);
            append_attr(attrs, "prio", event.a);
            emit_event(event, depth_of(stack, event.tid), "migrate", attrs);
        }
        break;
    case CG_KEV_PROC_FORK:
        if (is_target(event.tid)) {
            account_until(event.tid, event.ts, stack);
            std::string attrs;
            append_attr(attrs, "child", event.peer_tid);
            emit_event(event, depth_of(stack, event.tid), "fork", attrs);
        }
        break;
    case CG_KEV_PROC_EXIT:
        if (is_target(event.tid)) {
            account_until(event.tid, event.ts, stack);
            std::string attrs;
            append_attr(attrs, "prio", event.a);
            emit_event(event, depth_of(stack, event.tid), "exit", attrs);
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
    default:
        if (kernel_is_io_enter(event.kind) || kernel_is_io_exit(event.kind)) {
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
        auto& thread = threads_[tid];
        if (!thread.ops.empty())
            thread.partial = true;
        if (thread.partial)
            thread_counters_[tid].partial = true;
    }
}

std::string KernelTimeline::format_report(
    const std::vector<std::string>& names) const
{
    if (thread_counters_.empty())
        return {};

    std::vector<uint32_t> tids;
    tids.reserve(thread_counters_.size());
    for (const auto& [tid, counters] : thread_counters_) {
        (void)counters;
        tids.push_back(tid);
    }
    std::sort(tids.begin(), tids.end());

    std::string out = "Kernel:\n";
    for (uint32_t tid : tids) {
        const auto total_it = thread_counters_.find(tid);
        if (total_it == thread_counters_.end())
            continue;
        const KernelCounters& total = total_it->second;

        out += "  tid " + std::to_string(tid) + "\n";
        out += "    cpu=" + format_ns(total.cpu_ns);
        out += " runnable=" + format_ns(total.runnable_ns);
        out += " blocked=" + format_ns(total.blocked_total());
        out += " switches=" + std::to_string(total.switches);
        if (total.partial)
            out += " partial=yes";
        out += '\n';

        std::string reasons;
        for (size_t i = 0; i < kBlockReasonCount; ++i) {
            if (total.blocked_ns[i] == 0)
                continue;
            if (!reasons.empty())
                reasons += ' ';
            reasons += block_reason_name(static_cast<BlockReason>(i));
            reasons += '=';
            reasons += format_ns(total.blocked_ns[i]);
        }
        if (!reasons.empty())
            out += "    blocked(" + reasons + ")\n";

        std::vector<StatKey> keys;
        for (const auto& [key, counters] : function_counters_) {
            (void)counters;
            if (key.tid == tid)
                keys.push_back(key);
        }
        std::sort(keys.begin(), keys.end(), [](const StatKey& a,
                                               const StatKey& b) {
            if (a.depth != b.depth)
                return a.depth < b.depth;
            return a.function_id < b.function_id;
        });
        for (const StatKey& key : keys) {
            const KernelCounters& counters = function_counters_.at(key);
            const std::string name =
                key.function_id < names.size() ? names[key.function_id]
                                               : std::string("<unknown>");
            out += "    " + std::to_string(key.depth) + ". " + name;
            out += " cpu=" + format_ns(counters.cpu_ns);
            out += " runnable=" + format_ns(counters.runnable_ns);
            out += " blocked=" + format_ns(counters.blocked_total());
            out += '\n';
        }
    }
    return out;
}

std::string format_kernel_report(const KernelTimeline& timeline,
                                 const std::vector<std::string>& names)
{
    return timeline.format_report(names);
}

}  // namespace callgraph
