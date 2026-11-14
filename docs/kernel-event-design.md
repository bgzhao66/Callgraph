# Kernel event tracing design

Status: **P0 MVP implemented; P1/P2 are proposals.** Implemented today:
scheduler, futex, I/O syscalls, and block records, with a userspace
`KernelTimeline` report. Network, memory, PMU, IRQ/workqueue, and offline
kernel-line replay are not implemented. Sections below describe the full
target design; Section 16 records the P0 deviations.

## 1. Summary

`callgraph` currently explains *what* an application called, but not why a
call took time. A function can be slow because it executed instructions, was
preempted, waited on a futex, waited for a page fault or direct reclaim, waited
for a block device, or waited for a network socket. The function-call tree
cannot distinguish those cases.

This design adds a **second, correlated event stream**. Kernel events are
emitted by a separate BPF object, filtered in the kernel, and correlated with
the existing per-TID user call stack in userspace. They are never represented
as function entries or returns:

```text
1.234567890 4242 : 0 -> main
1.234567895 4242 : 1 -> process_request
1.234567900 4242 : 2 -> acquire_lock
1.234567901 4242 : 2 @FUTEX wait_begin id=1001 uaddr=0x7f8c... op=0x80
1.234567902 4242 : 2 @SCHED switch_out id=1002 next=4300 state=S
1.234568890 4242 : 2 @SCHED wakeup id=1002 by=4300 cpu=3
1.234568990 4242 : 2 @SCHED switch_in id=1002 prev=4300 offcpu_ns=1088000 runqueue_ns=100000
1.234568991 4242 : 2 @FUTEX wait_end id=1001 ret=0 duration_ns=1090000
1.234568992 4242 : 2 <- acquire_lock
1.234568993 4242 : 1 <- process_request
1.234568994 4242 : 0 <- main
```

The function tree, depths, and `->`/`<-` semantics are untouched. Kernel lines
use a distinct `@CATEGORY` marker and are associated with the top user frame
that was active on that TID.

The design is deliberately staged: scheduler and futex events first, then
syscall I/O and block I/O, then memory and network, and hardware performance
counters last. Every family is independently configurable and off by default.

Key decisions:

- The existing function BPF object, event ABI, `CallStack`, and text format
  are unchanged. Kernel events use a second BPF object, a second ring buffer,
  and an additive `@CATEGORY` line format.
- BPF is a stateless, filtered emitter. All scheduler, syscall, and interval
  state lives in userspace `KernelTimeline`, so live tracing and offline
  replay share one implementation.
- Time is partitioned by accounting at every function and kernel event
  boundary, not only at context switches. This keeps CPU/off-CPU attribution
  correct across function calls inside one scheduler slice.
- Raw observations and derived intervals are separate. Derived values are
  recomputed from timestamps on replay.
- Asynchronous kernel work is never charged to a function without a direct
  context or an explicit correlation key. Global events are reported
  separately.
- Tracepoint layouts are read from tracefs at runtime; no `vmlinux.h` or
  per-kernel hardcoded structs.

## 2. Goals and non-goals

Goals:

- Attribute kernel-side latency to the user function invocation that was
  running (or suspended) on the same TID.
- Preserve the distinction between **raw observations** and **derived
  intervals**, so a text trace can be re-analysed without re-running the
  target.
- Preserve the existing function event path byte-for-byte when kernel events
  are disabled.
- Keep kernel-event loss from corrupting call-stack reconstruction.
- Work with the existing text output, `--histogram`, OTLP export, and offline
  `export --otel`/`--flame` paths.
- Discover tracepoints and fields at runtime instead of assuming a kernel
  version or headers.

Non-goals:

- Replacing `perf`, `ftrace`, `bcc`, or `bpftrace`. This is a targeted
  correlation layer, not a general tracing front end.
- Attributing asynchronous kernel work to whichever target thread happens to
  be running. Causal links are marked as such; unrelated work is global.
- Capturing every kernel event. Families are opt-in and independently
  attachable.
- Full kernel stack unwinding. Kernel stack capture is a later extension.
- Proving causality. An off-CPU interval is *observed* in a function's
  context; the raw reason is reported separately.
- Application-level request IDs, packet payloads, file paths, or arbitrary
  user strings in ordinary mode.

## 3. Architecture

### 3.1 Two BPF objects, two event streams

The existing `bpf/trace.bpf.c` object, its 136-byte `cg_event`, and the
`events` ring buffer stay unchanged. Kernel events are emitted by a new
`bpf/kernel/trace.bpf.c` object into a separate `kernel_events` ring buffer.

```text
                 +-------------------------------+
                 | callgraph userspace controller|
                 +---------------+---------------+
                                 |
        +------------------------+------------------------+
        |                                                 |
  uprobe object                                     kernel object
  bpf/trace.bpf.o                                   bpf/kernel/trace.bpf.o
  events ring buffer                                kernel_events ring buffer
        |                                                 |
        +------------------------+------------------------+
                                 |
                          StreamMerger (timestamp order)
                                 |
             +-------------------+-------------------+
             |                                       |
        CallStack                              KernelTimeline
        function lines                         kernel lines
        histogram                              interval accounting
        OTel function spans                    OTel span events
```

Reasons for two objects and two ring buffers:

1. **Failure isolation.** A kernel tracepoint program that the verifier
   rejects on an older kernel must not break ordinary function tracing. The
   kernel object is loaded only when kernel events are requested.
2. **Loss isolation.** A flood of `sched_switch` or block events must not
   displace function entry/return events from the ring buffer. Losing a
   function event corrupts the shadow stack; losing a kernel event only
   reduces attribution.
3. **Compatibility.** The existing `cg_event` ABI, text format, and offline
   replay path remain untouched.
4. **Shared sizing.** `--ringbuf-size` sets the size of both the function and
   the kernel ring buffer. They remain separate maps, so the loss isolation
   above still holds.

The cost is that the two streams must be merged in timestamp order. A
bounded reorder window (Section 3.4) handles that.

A single tagged ring buffer was considered and rejected for the MVP: BPF
ring buffers have no priority, so a burst of high-frequency scheduler or block
events could evict function events. A single ring buffer also forces the
function record layout to grow a header or a union, changing a hot path that
works today.

### 3.2 Userspace pipeline

The collector remains single-threaded. It drains both ring buffers, merges
records by timestamp, and feeds one ordered pipeline:

```cpp
struct TimedEvent {
    uint64_t ts;
    enum class Source { Function, Kernel, Pmu };
    Source source;
    uint64_t sequence;   // tie-break within a source
    // FunctionEvent, KernelEvent, or PmuSample
};
```

Processing order for each merged event:

1. Account elapsed time up to `event.ts` for the affected TID(s) in the
   `KernelTimeline` (only when kernel tracing is enabled).
2. Apply the event: `CallStack::on_event()` for function events,
   `KernelTimeline::on_kernel()` for kernel events, or
   `KernelTimeline::on_pmu()` for samples.
3. Render the text line(s) through `Output`.
4. Notify the active span sink when OTel export is enabled.

Accounting before mutation is important: a function entry/return changes the
active user frame at that instant, so the interval that ended at the event
belongs to the *old* frame.

### 3.3 BPF stays stateless

The kernel BPF programs do **not** keep per-thread call depth, pending
operations, or execution state. They only:

- filter by target TID (and optionally descendants),
- read a small fixed set of tracepoint fields,
- fill a fixed-size record, and
- submit it to the kernel ring buffer.

All correlation state lives in `KernelTimeline` in userspace. This is a
deliberate departure from the common BPF design that keeps `thread_state`,
`call_depth`, and `pending_events` maps in the kernel:

- the same correlation code then runs for live tracing and offline replay;
- userspace can change the state machine without reloading BPF;
- the verifier sees short, branch-bounded programs;
- no per-event map updates or lock contention on the scheduler hot path;
- the raw trace remains the source of truth.

The only kernel-side state is the target-TID map (and the tracepoint field
offset/config maps), which is needed to filter before submission.

### 3.4 Event ordering

`bpf_ktime_get_ns()` is the single timestamp source for function and kernel
events. It returns `CLOCK_MONOTONIC` nanoseconds, matching `ClockConverter`.
A ring buffer preserves submission order per stream, but **not** a global
timestamp order across CPUs or across two ring buffers. Scheduler events on
different CPUs can be observed slightly out of timestamp order.

The merger therefore holds a small bounded window:

- Each stream keeps a timestamp-ordered deque.
- After draining both ring buffers, `watermark = max(last_seen_ts) -
  reorder_window`; records at or below the watermark are released in
  `(ts, source_rank, sequence)` order.
- `--merge-window` defaults to `1ms`. `0` disables reordering and is
  intended only for debugging.
- At shutdown, drain both ring buffers and flush the whole window.
- If a record arrives with a timestamp older than the last released record,
  it is still processed, counted as `out_of_order`, and marked
  `partial=true` for that TID. It is never silently dropped.

The window delays text output by at most the window size. Text lines are
still produced in the merger's order, so the trace file is deterministic for
a given window.

Tie-break at equal timestamps: function events are released before kernel
events; among the same source, the dequeue sequence decides. Exact-tie
attribution is best-effort and documented; nanosecond ties are rare.

## 4. Event model

### 4.1 Binary kernel record

`bpf/kernel_event.h` is shared by BPF and C++:

```c
#define CG_KERNEL_EVENT_VERSION 1

struct cg_kernel_event {
    __u64 ts;         // bpf_ktime_get_ns(), CLOCK_MONOTONIC
    __u32 tid;        // subject/current TID
    __u32 tgid;       // subject/current TGID (0 when unavailable)
    __u32 peer_tid;   // next/wake target/waker, event-specific
    __u32 peer_tgid;  // 0 when unavailable
    __u32 cpu;
    __u16 kind;       // CG_KEV_*
    __u8  category;   // CG_KCAT_*
    __u8  flags;      // CG_KF_*
    __u64 a, b, c, d, e, f, g, h;
};
```

The structure is exactly 96 bytes and naturally aligned. Eight generic words
are enough for the largest P0 payload (futex has six arguments plus the
syscall number and return value) without a union whose layout could drift
between BPF and C++.

Flags:

| Flag | Meaning |
| --- | --- |
| `CG_KF_BEGIN` | operation/interval begins |
| `CG_KF_END` | operation/interval ends |
| `CG_KF_DIRECT` | event executes in the subject TID's context |
| `CG_KF_CAUSAL` | linked by a key (device, socket, request) |
| `CG_KF_GLOBAL` | not attributable to a target thread |
| `CG_KF_PARTIAL` | captured after attach or after lost events |
| `CG_KF_INCOMPLETE` | begin/end pair was not completed |
| `CG_KF_LOST` | a lost-event marker, not a real observation |

Categories:

`SCHED`, `FUTEX`, `IO`, `BLOCK`, `NET`, `MM`, `PMU`, `IRQ`, `WORK`.

`kind` is a stable 16-bit enum. New kinds may be added; an older reader skips
unknown kinds rather than failing.

### 4.2 Payload conventions

The eight words are unnamed in the ABI so each event family can use them
without a union, but their meaning is fixed per kind:
| Kind | a | b | c | d | e | f | g | h |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `SCHED_SWITCH` | prev_state | prev_prio | next_prio | prev_cpu | next_cpu | | | |
| `SCHED_WAKEUP` | prio | success | target_cpu | | | | | |
| `SCHED_MIGRATE` | prio | orig_cpu | dest_cpu | | | | | |
| `PROC_FORK` | parent_pid | child_pid | | | | | | |
| `PROC_EXIT` | prio | | | | | | | |
| `FUTEX_ENTER` | nr | uaddr | op | val | utime | uaddr2 | val3 | |
| `FUTEX_EXIT` | nr | ret | | | | | | |
| `READ_ENTER` | nr | fd | buf | count | | | | |
| `READ_EXIT` | nr | ret | | | | | | |
| `WRITE_ENTER` | nr | fd | buf | count | | | | |
| `WRITE_EXIT` | nr | ret | | | | | | |
| `FSYNC_ENTER` | nr | fd | | | | | | |
| `FSYNC_EXIT` | nr | ret | | | | | | |
| `BLOCK_*` | dev | sector | nr_sector | bytes | error | | | |
| `PAGE_FAULT` | address | ip | error_code | | | | | |
| `DIRECT_RECLAIM_*` | order | gfp_flags | | | | | | |
| `PMU_SAMPLE` | event_id | period | ip | cpu | | | | |

Subject rules:

- `SCHED_SWITCH`: `tid` is the previous TID, `peer_tid` is the next TID.
  Both sides are target-checked independently.
- `SCHED_WAKEUP`/`SCHED_WAKING`/`SCHED_WAKEUP_NEW`: `tid` is the woken TID
  (the subject), `peer_tid` is the current/waker TID. The text line is
  rendered for the woken TID with `by=<peer>`.
- `SCHED_MIGRATE`, `PROC_EXIT`, syscalls, page faults, and reclaim:
  `tid` is the subject; `peer_tid` is zero.
- `PROC_FORK`: `tid` is the parent, `peer_tid` is the child.
- Global block/network/IRQ/work records: `tid` and `peer_tid` are zero and
  `CG_KF_GLOBAL` is set.

`tgid`/`peer_tgid` are best-effort context; filtering is TID-based because a
tracepoint often does not expose the peer's TGID.

Specific `kind` values (P0 set):

```text
SCHED_SWITCH, SCHED_WAKEUP, SCHED_WAKING, SCHED_WAKEUP_NEW,
SCHED_MIGRATE, PROC_FORK, PROC_EXIT,
FUTEX_ENTER, FUTEX_EXIT,
READ_ENTER, READ_EXIT, WRITE_ENTER, WRITE_EXIT,
PREAD64_ENTER, PREAD64_EXIT, PWRITE64_ENTER, PWRITE64_EXIT,
FSYNC_ENTER, FSYNC_EXIT, FDATASYNC_ENTER, FDATASYNC_EXIT,
OPENAT_ENTER, OPENAT_EXIT, CLOSE_ENTER, CLOSE_EXIT,
BLOCK_INSERT, BLOCK_ISSUE, BLOCK_COMPLETE, BLOCK_REQUEUE,
BLOCK_ERROR,
PAGE_FAULT_USER, PAGE_FAULT_KERNEL,
DIRECT_RECLAIM_BEGIN, DIRECT_RECLAIM_END,
NET_SOCKET, NET_CONNECT, NET_SEND, NET_RECV, NET_EPOLL_WAIT, NET_POLL,
TCP_RETRANSMIT,
PMU_SAMPLE
```

The `ENTER`/`EXIT` split is explicit so offline replay does not need a
per-architecture syscall table. `PMU_SAMPLE` is used only by the optional
BPF sampler in Phase 5c; the default perf collector feeds `PmuSample`
records directly into the merger.

### 4.3 Text format

Function lines are unchanged:

```text
<ts> <tid> : <depth> -> <function> [args]
<ts> <tid> : <depth> <- <function>
```

Kernel lines are additive:

```text
<ts> <tid> : <depth> @<CATEGORY> <event> [key=value ...]
```

Rules:

- `<depth>` is the depth of the top traced user frame on that TID at the
  event timestamp. It is `-` when the TID has no traced frame, and `*` when
  the event is global (not attributable to a TID).
- `@` is the discriminator. Function names may contain `@` (versioned ELF
  symbols), but function lines always have `->` or `<-` in the arrow column;
  kernel lines never do. The existing function regex therefore ignores old
  kernel lines, and the new kernel regex cannot consume function lines.
- Attribute values contain no unescaped spaces. Numeric values are decimal
  unless prefixed with `0x`. Kernel pointers are never printed; opaque
  correlation tokens are decimal.
- Durations are integer nanoseconds: `duration_ns`, `offcpu_ns`,
  `runqueue_ns`. Human-readable reports choose ns/us/ms/s per value.
- `id=` is a userspace-assigned monotonic correlation ID. It links a begin
  and end line, or the two views of one scheduler switch. It is stable for
  the trace, not across runs.
- `comm` and paths are not emitted by default. When added, they must be
  escaped or omitted from the space-separated format.

One raw kernel record may render as zero, one, or two lines. For example, a
`sched_switch` record with both `prev` and `next` in the target set renders a
`switch_out` line for the previous TID and a `switch_in` line for the next
TID. Each line is a state transition for exactly one TID; replay does not
double-count them. When a peer TID is also a target (a waker, or the other
side of a switch), the timeline advances that peer's accounting at the same
timestamp even if no text line is rendered for it.

`offcpu_ns`, `runqueue_ns`, and `duration_ns` on end lines are convenience
values. Offline replay recomputes them from timestamps and paired lines and
does not trust them for accounting. This keeps derived semantics changeable.

### 4.4 Correlation IDs

IDs are allocated by userspace, not BPF:

- On a syscall enter, allocate an ID and store it in the pending operation
  for `(tid, syscall, nesting)`.
- On the matching exit, reuse the ID and free it.
- On a switch-out, allocate an ID; the matching `switch_in` (the later
  `sched_switch` with `next == tid`) reuses it.
- On a block insert/issue, allocate or reuse an ID keyed by
  `(dev, sector, nr_sector)`.
- On a futex wait, the syscall enter/exit pair already has an ID.

IDs are only for human and offline correlation. The state machine does not
depend on them being globally unique across categories.

## 5. Correlation and attribution

### 5.1 Per-TID state

`KernelTimeline` owns one `ThreadRuntime` per TID:

```cpp
enum class CpuState { Unknown, OnCpu, Blocked, Runnable };

struct ThreadRuntime {
    CpuState state = CpuState::Unknown;
    uint64_t last_accounted_ns = 0;
    uint64_t offcpu_since_ns = 0;
    uint64_t runnable_since_ns = 0;
    uint32_t prev_state = 0;
    BlockReason reason = BlockReason::Unknown;

    // Innermost active kernel operations, used only to name the reason.
    std::vector<PendingOperation> syscalls;
    uint32_t reclaim_depth = 0;
    bool futex_wait = false;

    bool partial = false;
    uint64_t switches = 0;
    uint64_t out_of_order = 0;
};
```

`CallStack` exposes a read-only view of its current frames:

```cpp
std::span<const CallFrame> active_frames(uint32_t tid) const;
```

The span is root-first and empty when the TID has no traced frame. It is
valid only until the next `CallStack` mutation; the timeline consumes it
immediately. The timeline derives depth from the index. `CallFrame` gains
`invocation_id` and `root_id`. `invocation_id` is a monotonic per-`CallStack`
counter, assigned on entry. `root_id` is the invocation ID of the depth-0
frame (or the frame itself when no parent is traced). This gives every
interval a stable owner independent of OTel span tokens; `--histogram`
without an exporter still works.

When the timeline first accounts time for an invocation, it records
`(invocation_id, root_id, tid, depth, function_id)` in its own table. The
report can therefore resolve names and depths after `CallStack` has erased
the thread state on return.

Per-invocation counters are live only while the invocation is on the stack.
On return, the timeline folds them into the thread's `(depth, function_id)`
aggregate and releases the live entry. A long-running attach therefore grows
with distinct `(thread, depth, function)` keys, not with call count. Per-root
retention (Section 9.2) is deferred because it would keep one aggregate per
root invocation and needs an explicit cap.

`CallStack` notifies an optional frame-close observer for every closed frame
(normal return, skipped/desynced frame, or shutdown). The timeline folds the
invocation exactly once through that observer; it cannot rely only on the
top-of-stack exit event, because one return may close several frames above
the matching callee.

### 5.2 Account on every event boundary

Scheduler intervals alone are too coarse: a CPU slice can contain several
function calls. The timeline therefore accounts time at **every** function
and kernel event boundary:

```cpp
void KernelTimeline::account_until(uint32_t tid, uint64_t ts)
{
    auto& thread = threads[tid];
    if (thread.last_accounted_ns == 0) {
        thread.last_accounted_ns = ts;
        return;
    }
    if (ts <= thread.last_accounted_ns)
        return;

    const uint64_t delta = ts - thread.last_accounted_ns;
    switch (thread.state) {
    case CpuState::OnCpu:
        add_cpu(tid, delta);
        break;
    case CpuState::Blocked:
        add_blocked(tid, thread.reason, delta);
        break;
    case CpuState::Runnable:
        add_runnable(tid, delta);
        break;
    case CpuState::Unknown:
        break;
    }
    thread.last_accounted_ns = ts;
}
```

The top frame at the time of the boundary owns the interval exclusively. If
there is no traced frame, the interval goes to a synthetic `<no function>`
owner. The frame's ancestors include it, but the raw counters stay exclusive
to avoid double counting. Inclusive values are derived from the call tree at
report time, not summed from overlapping intervals.

Invariant, per observed invocation:

```text
wall_observed = cpu + blocked + runnable + unaccounted
```

`unaccounted` is zero when the first observed event is a switch-in or a
function entry, and is reported as `partial` otherwise. At shutdown, account
up to the stop timestamp and close any open operation as `incomplete`.

### 5.3 Scheduler state machine

For a target TID:

| Observation | Action |
| --- | --- |
| `switch_out` (`prev == tid`) | account on-CPU up to `ts`; set `offcpu_since=ts`; if `prev_state == R` set `Runnable` and `runnable_since=ts`, else `Blocked` with classified reason |
| `wakeup` (`target == tid`) | account up to `ts`; if `Blocked`, set `Runnable`, `runnable_since=ts`; if already `Runnable`, keep the first runnable timestamp; ignore if `OnCpu` |
| `switch_in` (`next == tid`) | account up to `ts`; compute `offcpu_ns = ts - offcpu_since` and `runqueue_ns = runnable_since ? ts - runnable_since : 0`; set `OnCpu`; clear interval markers |
| `migrate` | record `orig_cpu`/`dest_cpu`; no state change |
| `fork` | add the child TID to the target set; see Section 7.3 |
| `exit` | account up to `ts`, close open operations as incomplete, remove target TID |
| unknown | set `OnCpu` at `ts` and mark `partial`; do not invent prior time |

`prev_state == R` covers preemption: the task was runnable at switch-out, so
the whole off-CPU interval is runqueue wait. A wakeup after a preemption does
not restart `runnable_since`.

If a switch-in arrives with no recorded switch-out (attach started mid-run,
or events were lost), the timeline sets `OnCpu` and marks `partial`; it does
not report a fabricated off-CPU duration.

If a switch-in arrives without a wakeup, the blocked interval ends at
switch-in and `runqueue_ns=0`, with `wakeup_missing=1`. This is common when a
task was already runnable and `sched_wakeup` was filtered or lost.

`prev_state` is preserved raw. `S`/`D`/`R`/`T`/`Z`/`X` are classified for
display, but the raw value is always available in the text and metadata.

### 5.4 Blocking reason classification

State `S` or `D` says the task was not runnable; it does not say why. The
reason is chosen from the innermost active operation at switch-out, with this
precedence:

1. direct reclaim active -> `memory`
2. futex wait active -> `futex`
3. network syscall active (`send`, `recv`, `epoll_wait`, `poll`,
   `connect`, `accept`) -> `net`
4. I/O syscall active (`read`, `write`, `pread64`, `pwrite64`, `fsync`,
   `fdatasync`, `openat`, `sync_file_range`) -> `io`
5. `prev_state == D` with no active op -> `uninterruptible` (not `io`)
6. `prev_state == S` with no active op -> `sleep`
7. `prev_state == R` -> `runnable` (not a blocking reason)
8. anything else -> `other`

The raw `prev_state` and the active operation are both kept. A thread can be
in state `D` for reasons other than storage; the report must not call that
"disk I/O" without a matching I/O operation or block request.

A user-space spinlock, an uncontended `pthread_mutex_lock`, or a lock that
never enters the kernel produces no kernel event. The tool does not claim to
see those.

### 5.5 Attribution rules

There are three attribution classes, and they are never mixed silently:

- **Direct**: the event executes in the subject TID's context and the TID
  has a traced frame. Example: `read()` syscall enter/exit, `sched_switch`
  for the current task, direct reclaim on that task.
- **Causal**: the event is linked to an earlier target operation by a key,
  but executes in another context. Example: a block request issued by a
  worker or completed in a softirq, matched by `(dev, sector, nr_sector)`.
  It explains an I/O wait but is not attributed as CPU time to the thread.
- **Global**: no reliable link to a target thread. Example: `kswapd`,
  an unrelated interrupt, a TCP retransmit in softirq. It is reported in a
  separate global section and never charged to a function.

Scheduler preemption is direct attribution for *where* the thread was
executing, but the reason is `preempted`, not "this function caused the
delay". Reports keep the reason column.

### 5.6 Partial traces and lost events

`partial=true` when any of these occur:

- attach started after the target's first switch-in;
- a switch-in has no switch-out;
- a begin has no matching end at shutdown;
- events were lost or arrived out of order;
- the function stack was truncated by `--include`/`--exclude` or
  `--max-depth` (display only; attribution is compressed accordingly).

Partial time is reported as `unaccounted`, not guessed. Lost kernel events
increment per-category counters and are printed in the summary. Lost
function events remain the existing ring-buffer concern and are not hidden by
the new stream.

At shutdown the collector drains both streams, flushes the merge window, and
then closes live frames through the same frame-close observer (with a
`shutdown` reason) before rendering the histogram or kernel report. This
ensures live invocations are folded exactly once even when no OTel exporter
is configured.

## 6. Event families

Priorities follow the proposal: P0 first, P1 next, P2 optional.

| Family | Priority | Phase | Direct attribution |
| --- | --- | --- | --- |
| Scheduler | P0 | 1 | switch/wakeup per TID |
| Futex | P0 | 2 | syscall in target TID |
| I/O syscalls | P0 | 2 | syscall in target TID |
| Block layer | P0 | 3 | causal, global by default |
| Memory | P1 | 4 | page fault/reclaim in target TID |
| Network | P1 | 4 | syscalls direct; tracepoints global |
| PMU | P1/P2 | 5 | sampled IP/counts |
| IRQ, workqueue, other | P2 | 6 | global, unless target context |

### 6.1 Scheduler (P0)

Tracepoints:

| Tracepoint | Fields used | Purpose |
| --- | --- | --- |
| `sched:sched_switch` | `prev_pid`, `prev_state`, `prev_prio`, `next_pid`, `next_prio` | context switches, off-CPU, on-CPU |
| `sched:sched_wakeup` | `pid`, `prio`, `success`, `target_cpu` | runnable start |
| `sched:sched_waking` | `pid`, `prio`, `success`, `target_cpu` | wakeup propagation detail |
| `sched:sched_wakeup_new` | same as wakeup | new task becomes runnable |
| `sched:sched_migrate_task` | `pid`, `prio`, `orig_cpu`, `dest_cpu` | migration |
| `sched:sched_process_fork` | `parent_pid`, `child_pid` | follow threads/children |
| `sched:sched_process_exit` | `pid`, `prio` | stop tracking |

Derived per TID: CPU time, off-CPU time split into blocked and runqueue wait,
switch count, migration count, and blocked reason. `sched_stat_*` is not used;
it adds another high-frequency family without adding attribution the switch
pair does not already provide.

Text:

```text
<ts> <tid> : <d> @SCHED switch_out id=... next=... state=S
<ts> <tid> : <d> @SCHED wakeup id=... by=... cpu=...
<ts> <tid> : <d> @SCHED switch_in id=... prev=... offcpu_ns=... runqueue_ns=...
<ts> <tid> : <d> @SCHED migrate orig_cpu=... dest_cpu=...
<ts> <tid> : <d> @SCHED fork child=...
<ts> <tid> : <d> @SCHED exit
```

`sched_switch` runs in the context of the outgoing task, but the record
contains both PIDs. The userspace renderer emits a `switch_out` line for the
outgoing target and a `switch_in` line for the incoming target. It never
uses `bpf_get_current_pid_tgid()` as the subject of a scheduler event.

### 6.2 Synchronization: futex (P0)

Attach `syscalls:sys_enter_futex` / `syscalls:sys_exit_futex` (not the
`raw_syscalls` pair; see Section 7.2). Fields:

- enter: `uaddr`, `op`, `val`, `utime` (timeout pointer), `uaddr2`, `val3`
- exit: `ret`

Text:

```text
<ts> <tid> : <d> @FUTEX wait_begin id=... uaddr=0x... op=0x...
<ts> <tid> : <d> @FUTEX wait_end id=... ret=... duration_ns=...
<ts> <tid> : <d> @FUTEX wake id=... uaddr=0x... count=...
```

`wait_begin`/`wait_end` are emitted for wait-family operations
(`FUTEX_WAIT`, `FUTEX_WAIT_BITSET`, `FUTEX_WAIT_REQUEUE_PI`); wake-family
operations emit `wake`. The command is `op & 0x7f`; `FUTEX_PRIVATE_FLAG` and
`FUTEX_CLOCK_REALTIME` are reported separately.

The syscall duration includes CPU time, sleeping, and runqueue wait. Reports
do not add it to the blocked interval; the scheduler state machine already
partitions that time. The futex interval is the **operation** view; the
scheduler intervals are the **execution-state** view.

Kernel `futex_wait`/`futex_wake` function probes are not used in the MVP.
They are implementation-specific and add kprobe fragility. `pthread_mutex_*`
uprobes are a later optional feature; the uncontended fast path never enters
the kernel.

### 6.3 Storage: syscalls and block layer (P0)

Syscall tracepoints (direct attribution):

| Operation | Enter fields | Exit field |
| --- | --- | --- |
| `read` | `fd`, `buf`, `count` | `ret` |
| `write` | `fd`, `buf`, `count` | `ret` |
| `pread64` | `fd`, `buf`, `count`, `pos` | `ret` |
| `pwrite64` | `fd`, `buf`, `count`, `pos` | `ret` |
| `fsync` | `fd` | `ret` |
| `fdatasync` | `fd` | `ret` |
| `openat` | `dfd`, `filename`, `flags`, `mode` | `ret` |
| `close` | `fd` | `ret` |
| `sync_file_range` | `fd`, `offset`, `nbytes`, `flags` | `ret` |

`openat` captures the filename pointer, not the string. Reading user strings
is optional and off by default. `read`/`write` return values are captured;
the requested count and actual transfer are both available. A successful
buffered `write` is not durable; `fsync`/`fdatasync` is the durability
measure.

Block tracepoints (global/causal):

| Tracepoint | Fields used |
| --- | --- |
| `block:block_rq_insert` | `dev`, `sector`, `nr_sector`, `bytes` |
| `block:block_rq_issue` | `dev`, `sector`, `nr_sector`, `bytes` |
| `block:block_rq_complete` | `dev`, `sector`, `nr_sector`, `error` |
| `block:block_rq_requeue` | `dev`, `sector`, `nr_sector` |
| `block:block_rq_error` | `dev`, `sector`, `nr_sector`, `error` |

Derived:

```text
queue_ns   = issue - insert
device_ns  = complete - issue
total_ns   = complete - insert
```

Requests may be merged, split, requeued, or completed partially. There is no
guaranteed one-to-one mapping from a syscall to a block request. Pending
requests are matched by `(dev, sector, nr_sector)` with a FIFO per key. An
issue/complete with no insert starts a new key; an unmatched completion is
emitted with `unmatched=1`, not discarded. A negative derived duration from
reordering is clamped and marked `reordered=1`.

`dev_t` is printed as `major:minor`, not as a raw number. Block events are
global by default: a completion often runs in a softirq or worker, not in the
target thread. If `--block-devices` is supplied, the BPF program filters by
the device map before reserving ring-buffer space.

Filesystem-specific tracepoints (`ext4_sync_file_*`, `xfs_*`, `writeback:*`)
are optional P1 add-ons. They are discovered, not assumed.

### 6.4 Memory (P1)

| Tracepoint/probe | Fields | Notes |
| --- | --- | --- |
| `exceptions:page_fault_user` | `address`, `ip`, `error_code` | may be absent |
| `exceptions:page_fault_kernel` | `address`, `ip`, `error_code` | may be absent |
| `vmscan:mm_vmscan_direct_reclaim_begin` | `order`, `gfp_flags` | per-thread |
| `vmscan:mm_vmscan_direct_reclaim_end` | `order` | duration |

Page-fault tracepoints are point events, not begin/end pairs. The error code
does not reliably distinguish major from minor faults, so the text says
`page_fault` and reports the raw error code; it does not label every fault
"major". Aggregate major/minor counts can come from `perf_event_open`
software counters or `/proc/<pid>/stat` deltas later.

Direct reclaim begins and ends on the target thread and is a real latency
interval. It is attributed directly and is the highest-precedence blocking
reason. `kswapd_wake`/`kswapd_sleep`, compaction, and `kmem` events are
global or high-volume; they are not charged to the target function.

### 6.5 Network (P1)

Direct (syscall) events:

| Operation | Fields |
| --- | --- |
| `socket` | `family`, `type`, `protocol` |
| `connect` | `fd`, address pointer, `addrlen` |
| `accept4` | `fd`, address pointers, `flags` |
| `sendto` / `recvfrom` | `fd`, buffer, `len`, `flags`, address |
| `sendmsg` / `recvmsg` | `fd`, message pointer, `flags` |
| `epoll_wait` | `epfd`, `events`, `maxevents`, `timeout` |
| `poll` | `fds`, `nfds`, `timeout` |

`epoll_wait` duration is especially useful: it separates a server waiting for
requests from a server processing them. Socket syscall durations are direct;
their `EAGAIN` returns are not waits and must not be reported as latency.

Kernel network tracepoints (`sock:inet_sock_set_state`,
`tcp:tcp_retransmit_skb`, `tcp:tcp_send_reset`, `net:net_dev_queue`,
`net:net_dev_xmit`, `netif_receive_skb`) are **global** in the MVP. They do
not carry a target TID, and a retransmit or packet processing run in a
softirq cannot be charged to the application function that happens to be
running. They are opt-in, filtered by interface/address where possible, and
reported in the global section. Causal socket correlation is a later
extension; the trace format already has `CG_KF_CAUSAL` for it.

A successful `send` does not mean the peer received or processed the data.
End-to-end RPC latency needs application request IDs, which are out of scope.

### 6.6 CPU hardware performance events (P1/P2)

Hardware counters are not tracepoints and are not intervals. They are handled
by a separate `PerfCollector` using `perf_event_open()`.

Events:

`cycles`, `instructions`, `cache-references`, `cache-misses`,
`branch-instructions`, `branch-misses`, `L1-dcache-load-misses`,
`LLC-load-misses`, `dTLB-load-misses`, `iTLB-load-misses`,
`stalled-cycles-frontend`, `stalled-cycles-backend` (when supported).

**Mode A: counting.** Open a per-thread group (`PERF_FORMAT_GROUP |
PERF_FORMAT_TOTAL_TIME_ENABLED | PERF_FORMAT_TOTAL_TIME_RUNNING`) for the
target threads and read it at shutdown. This gives per-thread totals. It does
not give per-function attribution. It is cheap and useful for "how much work
did this thread do", not "which function caused the cache misses".

**Mode B: sampling.** Open a sampling event with
`PERF_SAMPLE_IP | PERF_SAMPLE_TID | PERF_SAMPLE_TIME | PERF_SAMPLE_CPU |
PERF_SAMPLE_PERIOD`, mmap a per-CPU or per-thread ring, and parse
`PERF_RECORD_SAMPLE`. Map the sampled IP to a function through the existing
ELF resolver. Samples are approximate (skid); a cache miss is not a latency
and must not be printed as a duration.

The MVP uses the kernel's perf ring buffer, not a BPF perf-event program.
Perf already provides sampling, CPU/TID fields, and loss records; adding a
BPF program and a stack-trace map increases complexity without improving the
IP-only attribution. A later Phase 5c can attach a BPF program to the perf
event for `bpf_get_stackid()` call-chain capture, if stack attribution
justifies it.

Report raw counts, `enabled_ns`/`running_ns`, and a `multiplexed` flag when
the counters were not scheduled for the whole interval. Do not scale counts
silently.

`perf_event_paranoid` and `CAP_PERFMON` are checked at startup. If PMU access
is denied, other families continue and the summary explains why PMU is
missing.

### 6.7 Other events (P2)

After the core families:

| Category | Events | Attribution |
| --- | --- | --- |
| `IRQ` | `irq:irq_handler_entry/exit`, `irq:softirq_entry/exit` | global, unless running in target context |
| `WORK` | `workqueue:workqueue_execute_start/end` | causal/global |
| `MM` | `compaction:*`, `filemap:*`, `oom:*` | global/point |
| `SCHED` | `sched_process_exec` | lifecycle |
| `IO` | `writeback:*`, filesystem `fsync` probes | causal |
| `LOCK` | selected `lock:*` tracepoints | diagnostic, not latency |

These are not enabled by `--events` presets except `full`. Some can
produce very high event volumes and are documented as such.

## 7. Discovery and BPF implementation

### 7.1 Tracefs discovery

At startup:

1. Find tracefs at `/sys/kernel/tracing` or `/sys/kernel/debug/tracing`.
2. Read `available_events` to build the set of available `group:name`
   tracepoints.
3. For each requested family, resolve its event list. An alias table maps
   logical names to kernel names (for example `sched_wakeup` vs
   `sched_wakeup_new`).
4. Read each enabled event's `format` file and extract the `field:` name,
   `offset:`, `size:`, and `signed:` values.
5. Validate that every field the BPF program needs exists and has an
   acceptable size (4 or 8 bytes). Missing or `__data_loc` fields disable
   that specific event with a warning; they do not abort the session unless
   `--require-events` is set.
6. Record the tracefs path, kernel release, available/missing events, and
   field layouts in `--trace-metadata` so an offline trace is reproducible.

`__data_loc` strings (`comm`, `rwbs`, `filename`) are skipped in the MVP.
They require a second bounded read and would add variable-length records.

### 7.2 Field offsets without vmlinux.h

The project does not use `vmlinux.h` or CO-RE today; adding a kernel-version
header would be a large build change. Instead, the tracepoint `format` file
provides runtime offsets, and userspace writes them into a BPF array map:

```c
struct cg_tp_config {
    __u16 offset[CG_TP_MAX_FIELDS];
    __u8  size[CG_TP_MAX_FIELDS];
};
```

Each event program looks up its config once, then reads fields with
`bpf_probe_read_kernel(&value, size, (char*)ctx + offset)`. Fixed-size reads
are branch-selected (4 or 8 bytes); no variable-length reads. This keeps
programs short and works across kernel versions without hardcoded structs.

This approach must be prototyped against the supported kernels before the
rest of the design is committed. If the verifier rejects a variable context
offset, the fallback is a generated per-kernel field struct or a small
BTF/CO-RE reader, not a hardcoded table of offsets per kernel release.

### 7.3 Target filtering

Filtering happens in BPF, before `bpf_ringbuf_reserve()`:

- `target_tids` is a hash map of TIDs to a small flags value.
- `target_tgids` is a fallback hash map for process-wide matching.
- Userspace populates both at startup from `/proc/<pid>/task` and
  `/proc/<pid>/status`.
- `sched_process_fork` inserts the child TID into `target_tids` if the
  parent is a target. This avoids a blind spot for newly created threads.
  Userspace resolves the child's TGID from `/proc`; if `--children` is off
  and the child is a new process, it removes the child's TIDs again. The
  brief over-capture window is preferable to missing a new thread's first
  events.
- `sched_process_exit` removes the TID.
- `--children` keeps descendants; without it, only the target process and
  its threads are kept.
- `--tid` restricts to explicit TIDs; `--system-wide` bypasses filtering.
- If `sched_process_fork` is unavailable, userspace falls back to periodic
  `/proc/<pid>/task` reconciliation. New threads then have a larger
  `partial` window.

Scheduler filtering checks **both** sides of the event:

```text
emit if target(prev_tid) or target(next_tid)
```

This is necessary because a `sched_switch` involving a target thread may
execute in the other task's context. The same applies to `sched_wakeup`
(target or waker) and `sched_migrate_task` (subject). Scheduler fields expose
TIDs, not TGIDs, so the scheduler path depends on the TID map; the TGID
fallback is used where a TGID is available, such as the current task in a
syscall or reclaim event.

The userspace target list is updated asynchronously; a new thread can execute
a few instructions before its TID reaches the BPF map. This is a documented
`partial` window. Function events are not affected because uprobes are
attached with the target PID filter, not the kernel TID map.

### 7.4 BPF object layout, maps, and programs

```text
bpf/kernel/trace.bpf.c        # single translation unit, includes modules
bpf/kernel/common.bpf.h       # record layout, helpers, categories
bpf/kernel/maps.bpf.h         # shared map definitions
bpf/kernel/sched.bpf.c
bpf/kernel/syscall.bpf.c
bpf/kernel/block.bpf.c
bpf/kernel/mm.bpf.c
bpf/kernel/net.bpf.c
bpf/kernel/irq.bpf.c          # later
```

A single translation unit keeps the existing embedded-object build simple.
Modules are included in a fixed order; all maps are defined once in
`maps.bpf.h`.

Maps:

| Map | Type | Purpose |
| --- | --- | --- |
| `kernel_events` | ringbuf | kernel records |
| `kernel_lost` | per-CPU array | lost counts per category |
| `target_tids` | hash | exact TID filter |
| `target_tgids` | hash | process fallback |
| `tp_config` | array | field offsets per event kind |
| `block_devices` | hash | optional device filter |
| `kernel_config` | array | family bitmask and options |

Program names are stable because userspace attaches them individually:

```text
cg_sched_switch, cg_sched_wakeup, cg_sched_waking, cg_sched_wakeup_new,
cg_sched_migrate, cg_proc_fork, cg_proc_exit,
cg_sys_enter_futex, cg_sys_exit_futex,
cg_sys_enter_read, cg_sys_exit_read, ...
cg_block_insert, cg_block_issue, cg_block_complete,
cg_page_fault_user, cg_direct_reclaim_begin, cg_direct_reclaim_end
```

`KernelProbeManager` loads the embedded `kernel_bpf_o` only when at least one
kernel family is enabled, sets ring-buffer size, populates maps, and attaches
only the selected programs. A missing event means the program is not
attached; the rest of the session continues.

Per-syscall tracepoints are used instead of `raw_tp/sys_enter` +
`raw_tp/sys_exit`. Raw syscall programs run for every syscall on every CPU,
even with an early target check. Per-syscall tracepoints run only for the
selected syscall, and their named fields avoid `pt_regs` layout assumptions.
The cost is more programs and more attach calls, which is acceptable for the
small P0 set.

### 7.5 PMU collector

`PerfCollector` is separate from the BPF object. It opens perf events for the
target threads (or per CPU under `--system-wide`), drains its ring buffers,
and feeds samples into the merger with `Source::Pmu`. It sets
`use_clockid=1` and `clockid=CLOCK_MONOTONIC` so `PERF_SAMPLE_TIME` matches
`bpf_ktime_get_ns()`; if that is unsupported, samples are timestamped at
userspace receipt and marked `approximate=true`.

## 8. Command-line interface

Kernel events are opt-in: `--kernel` is the master switch, and every other
kernel option is secondary to it. Without `--kernel`, the CLI and output are
unchanged. `--kernel` alone selects the `latency` preset. In `--help`,
`--kernel` is printed once and its family shortcuts and modifiers are indented
beneath it.

```text
# Default families (latency preset: sched, futex, io, block)
callgraph attach -p 4242 --kernel

# Scheduler only
callgraph attach -p 4242 --kernel --sched

# Synchronization
callgraph attach -p 4242 --kernel --futex

# Storage syscalls and block layer
callgraph attach -p 4242 --kernel --io --block

# Presets
callgraph attach -p 4242 --kernel --preset latency
callgraph attach -p 4242 --kernel --preset database
callgraph attach -p 4242 --kernel --preset cpu
callgraph attach -p 4242 --kernel --preset full

# Explicit family list
callgraph attach -p 4242 \
    --kernel --events sched,futex,io,block,mm

# Follow new threads and child processes
callgraph attach -p 4242 --kernel --children --sched

# Hardware performance counters
callgraph attach -p 4242 --pmu cycles,instructions,cache-misses
callgraph attach -p 4242 --pmu cache-misses --pmu-sampling 100000

# System-wide kernel events (no user-stack attribution)
callgraph attach --kernel --system-wide --sched
```

| Option | Meaning |
| --- | --- |
| `--kernel` | master switch; enables kernel tracing and defaults to `latency` |
| `--events LIST` | comma-separated `sched,futex,io,block,net,mm,pmu,irq,work` or `all` |
| `--sched`, `--futex`, `--io`, `--block`, `--network`, `--memory` | family sugar |
| `--preset NAME` | `latency`, `database`, `cpu`, `full` |
| `--tid TID` | restrict to explicit TIDs (repeatable/comma-separated) |
| `--children` | follow child processes as well as threads |
| `--system-wide` | bypass target filtering; no user-stack attribution |
| `--report` | append the `Kernel:` summary section |
| `--merge-window NS` | timestamp reorder window (default 1ms) |
| `--ringbuf-size SIZE` | size of both the function and kernel ring buffers (default 16m) |
| `--block-devices LIST` | restrict block tracepoints to `major:minor` devices |
| `--require-events` | fail if a requested tracepoint is unavailable |
| `--pmu LIST` | hardware counters to open |
| `--pmu-sampling PERIOD` | sampling period; omit for counting mode |
| `--otel-kernel-events` | attach raw kernel events as OTel span events |
| `--otel-kernel-spans` | emit derived intervals as child spans (off by default) |

`--events` is deliberately namespaced under `--kernel` rather than being a
generic top-level option, so it cannot be confused with function filters.
`--events pmu` opens the default counter set
(`cycles,instructions,cache-misses,branch-misses`); `--pmu` overrides that
list.

Validation:

- `--system-wide` requires root or the relevant capabilities and is allowed
  in `attach`; in `run` it still traces only the child's user functions but
  all kernel events. System-wide records use `*` depth and are aggregated
  globally; per-function timeline accounting is disabled because there is no
  target TID. `attach` currently requires `-p`; system-wide attach relaxes
  that requirement. `--system-wide` is incompatible with `--tid` and
  `--children`.
- Every kernel sub-option, including the `--sched`, `--futex`, `--io`, and
  `--block` shortcuts, is a usage error without `--kernel`.
- `--block-devices` requires `--block`.
- `--preset` and `--events` are additive; repeating `--events` appends
  families.
- `--pmu-sampling` requires `--pmu`.
- `--tid` and `--children` are mutually exclusive.
- `--report` without a kernel family is a usage error.
- `--events` with `--exporter` is valid; kernel events go to the text
  stream and, if enabled, to span events.
- `--dry-run` lists selected functions and available kernel events without
  attaching.

Presets:

| Preset | Families |
| --- | --- |
| `latency` | sched, futex, io, block, mm |
| `database` | sched, futex, io, block, mm |
| `cpu` | sched, pmu |
| `full` | sched, futex, io, block, net, mm, irq, work |

`latency` and `database` are intentionally the same for the MVP; they can
diverge once filesystem-specific probes are added.

## 9. Output and reports

### 9.1 Raw text

Raw text is the primary artifact and the input to offline replay. It contains
both function and kernel lines in timestamp order. With kernel events off,
the byte stream is unchanged.

`Output` gains:

```cpp
void emit_kernel(uint64_t ts, uint32_t tid, int depth,
                 const char* category, const std::string& event,
                 const std::string& attributes);
```

It shares the existing writer queue and timestamp formatting. Kernel lines
are lower priority: when the queue is over a soft limit, a kernel line is
dropped and counted; a function line may still be queued until the hard
limit. This keeps a kernel-event flood from delaying or dropping function
lines as quickly. The summary reports `output_dropped_kernel`.

`--max-depth` applies to kernel lines whose associated depth exceeds the
limit; `-` and `*` lines are always shown. Statistics still cover hidden
depths.

`--indent` applies to the depth column just as it does for function names,
using spaces before the `@CATEGORY` token.

### 9.2 Kernel report

`--report` (and `--histogram` when a kernel family is enabled) appends
a `Kernel:` section. If both are given, the section is rendered once. The MVP
section is per thread, after that thread's roots, to avoid depending on
per-root invocation identity:

```text
Kernel:
  tid 4242
    wall        1.250ms
    on-cpu       210us   16.8%
    blocked     1.040ms   83.2%
      futex     1.000ms
      io           40us
      sleep         0
      memory        0
    runnable      15us
    switches      12
    partial       no

  exclusive by depth/function:
    1. process_request   cpu=200us  runnable=15us  blocked=1.04ms
       reason=futex (1.00ms), io (40us)
```

`on-cpu + blocked + runnable` is the observed wall interval. `blocked` is
split by reason; the reasons are mutually exclusive. `exclusive` means the
top-frame time; callers include it in their wall time but not in their
exclusive counters.

A later revision can pair the `Kernel:` section with each root, using the
invocation IDs added in Section 5.1. That requires deciding how to render a
root whose kernel intervals began before its first function entry; it is
deferred.

Units are chosen per value from `choose_unit()`, as the tree report already
does. No kernel bar is added to the histogram in the MVP; a bar would imply
a share of a root span, which is only meaningful once per-root pairing is
defined.

### 9.3 OTel and Jaeger

Raw kernel events become **span events** on the function span that owns the
active frame:

```text
span: process_request
  event: futex_wait
    time: 1234567901
    attributes:
      callgraph.kernel.category = FUTEX
      callgraph.kernel.event = wait_begin
      callgraph.kernel.id = 1001
      callgraph.kernel.uaddr = 0x...
```

Derived exclusive intervals become attributes on the owning function span:

```text
callgraph.kernel.cpu_ns
callgraph.kernel.runnable_ns
callgraph.kernel.blocked_ns
callgraph.kernel.blocked.futex_ns
callgraph.kernel.blocked.io_ns
callgraph.kernel.blocked.memory_ns
callgraph.kernel.blocked.sleep_ns
callgraph.kernel.blocked.other_ns
callgraph.kernel.attribution = direct | preempted
callgraph.kernel.partial = true
```

`SpanSink` gains a default no-op kernel callback:

```cpp
virtual void on_kernel_event(uint32_t tid, uint64_t span_token,
                             const KernelEvent& event) {}
```

`SpanGenerator` attaches the event to the token's span, dropping it if the
span has already closed. A per-span event cap (for example 128) prevents a
high-frequency scheduler or block stream from exploding a trace; dropped
events are counted in `callgraph.kernel.events_dropped`.

`--otel-kernel-spans` optionally creates child spans for derived intervals
at or above a threshold, with `callgraph.kernel.span=true`. It is off by
default because a long `epoll_wait` would otherwise add a span per loop
iteration. Global events are not attached to arbitrary spans; an optional
`--otel-global-kernel` attaches them to the root span with
`attribution=global`.

### 9.4 Offline replay

`TraceParser` gains a second regex:

```text
^(\S+) (\d+) : (\d+|-|\*) @([A-Z]+) ([a-z0-9_]+)((?: [A-Za-z0-9_.:-]+=[^ ]+)*)$
```

Function lines are matched by the existing regex first, so the behavior of
old traces is unchanged. Kernel lines are parsed into `KernelEvent` records
and fed to `KernelTimeline`; they never enter `CallStack` and never change
depth. Unknown categories/kinds are counted in `ignored_lines`, not treated
as errors.

`TraceParseStats` gains `kernel_lines`, `kernel_events`, `bad_kernel_lines`,
and `unknown_kernel_events`. `--input-show-args` and the legacy `[args]`
handling remain function-only.

`callgraph export --otel` replays function and kernel events through the same
merger/timeline path, so span attributes and span events match a live trace.
`callgraph export --flame` ignores kernel lines; folded stacks remain
function-only.

`--trace-metadata` records the kernel configuration and discovery results.
An offline exporter can warn when a trace contains kernel lines but its
metadata says no kernel family was enabled, or when a requested field layout
is missing.

## 10. Performance and overhead

Policy:

- Default off: no kernel object, no additional BPF programs, no extra
  ring buffer, no timeline accounting.
- Filter target TIDs in BPF before reserve; sched events check both sides.
- Prefer tracepoints over kprobes; no kprobes in the P0 set.
- No kernel stack unwinding, no user string reads, no formatting in BPF.
- Fixed-size records; no per-event map updates in the scheduler path.
- Separate ring buffers with independent loss counters.
- Attach only selected families and programs.
- Per-syscall tracepoints rather than system-wide raw syscalls.
- Drop kernel text lines before function lines under output backpressure.
- Expose lost counts by category and `partial` flags.

High-frequency families (`sched_switch`, block, network, IRQ) still run a BPF
program for every event system-wide because tracepoints are global. The
target check is the first operation, so non-target events do not reserve
ring-buffer space, but the program invocation cost remains. Users must
measure on their workload; the integration suite includes a before/after
runtime check for the example programs, not a production benchmark.

Guidelines:

| Family | Relative cost | Mitigation |
| --- | --- | --- |
| sched | high invocation rate | target filter; only transitions |
| futex | low/medium | selected syscall tracepoint |
| I/O syscalls | medium | target filter; selected calls |
| block | high | device filter; opt-in |
| mm | low/medium | direct reclaim only; faults opt-in |
| net tracepoints | high | opt-in/global |
| PMU counting | low | per-thread group |
| PMU sampling | high | period; per-CPU or per-thread |

`--ringbuf-size` sizes both ring buffers and should be chosen for the workload.
Lost events are reported as `kernel_lost[category]`, never silently ignored.

## 11. Security, namespaces, and privileges

- Kernel tracing needs root or `CAP_BPF` + `CAP_PERFMON` (`CAP_SYS_ADMIN` is
  commonly required for tracefs/perf on older kernels). `--system-wide` and
  PMU sampling have the strictest requirements.
- `perf_event_paranoid` is checked before opening PMU events. A denied PMU
  does not disable sched/futex/I/O.
- `kernel.perf_event_paranoid`, tracefs permissions, and kernel lockdown can
  each prevent part of the design. Errors are explicit and per-family.
- Never print raw kernel pointers. User addresses (futex `uaddr`, buffers)
  may be printed because they belong to the traced process, but they are
  optional and can be suppressed.
- `comm` and path strings are not captured in the MVP; if added, they are
  escaped and bounded.
- BPF reads only the tracepoint context and bounded fields; no arbitrary
  kernel memory walk, no `bpf_probe_read_user` except explicit optional
  string capture.
- PID namespaces: `bpf_get_current_pid_tgid()` reports the kernel's PID
  values, while `/proc` may show namespace PIDs. In a container, resolve the
  target's host TIDs from `/proc/<pid>/status` `NSpid` before populating the
  BPF maps. The trace stores host TIDs; metadata records the mapping. Native
  host tracing needs no translation. A later enhancement can use
  `bpf_get_ns_current_pid_tgid()` with the target PID namespace.
- Cgroup-scoped filtering (`bpf_get_current_cgroup_id`) is a possible
  alternative for containers, but it cannot distinguish threads inside the
  cgroup; TID filtering remains the default.

## 12. Testing

Unit tests (`tests/unit/test_main.cpp`):

- Kernel record size/alignment/version static asserts.
- Text formatting and parsing round-trip for every kind, including `-`/`*`
  depth and escaped/empty attributes.
- Old function-only traces parse exactly as before; kernel lines are ignored
  by the function path.
- Scheduler state machine: switch-out/in, wakeup, preemption, missing wakeup,
  missing switch-out, migration, exit.
- Accounting invariant `cpu + blocked + runnable + unaccounted == wall` for
  synthetic timelines.
- Block reason precedence (reclaim > futex > net > io > uninterruptible >
  sleep).
- Interval accounting across function entry/return boundaries; exclusive
  attribution to the top frame, no double counting.
- Merger ordering, tie-break, reorder window, out-of-order records, shutdown
  flush.
- Lost-event counters and `partial` propagation.
- Report units and column layout; no `0.00` for nonzero durations.
- OTel span-event attachment, per-span cap, closed-span drop.
- Target map updates and fork/exit lifecycle with a fake tracefs/registry.

Integration (`tests/integration.sh`, root only for tracing):

- `examples/` additions: `futex_wait.cpp`, `fsync.cpp`, `sleep.cpp`,
  `page_fault.cpp`, `cpu_spin.cpp`.
- `--sched`: a sleeping/blocking example produces `@SCHED switch_out`,
  `wakeup`, `switch_in`; off-CPU > 0; runqueue >= 0.
- `--futex`: contended mutex/condvar produces `@FUTEX wait_begin/wait_end`;
  durations are positive and pair.
- `--io`: `fsync` produces `@IO fsync_begin/fsync_end`; a buffered `write`
  is not reported as durable.
- `--block`: writes to a file backed by a block device produce insert/issue/
  complete lines; unmatched completions are possible and marked.
- `--memory`: a large anonymous mapping touched page by page produces
  `@MM page_fault`; direct reclaim is exercised only when the test can force
  memory pressure (otherwise skip).
- `--pmu`: when permitted, `cycles`/`instructions` counts are nonzero and
  consistent with `perf stat`; sampling produces a sample count.
- `--report`: `cpu + blocked + runnable` is within tolerance of wall
  for a synthetic sleep workload.
- `--exporter otlp-json` with kernel events: function spans carry
  `callgraph.kernel.*` attributes and span events; no invalid OTLP.
- Offline replay of a hand-written trace with kernel lines matches live
  accounting.
- Without kernel flags, output is byte-identical to the current build for a
  deterministic example.
- Missing tracepoint simulation: an unavailable family warns and continues,
  or fails with `--require-events`.
- Capability checks: non-root kernel tracing fails with a clear message;
  non-root integration skips tracing as it does today.

Kernel matrix: at least one 5.15, one 6.1, and one 6.6+ kernel (uprobe_multi
path), x86-64. The tracepoint-format reader is the main portability risk.

## 13. Implementation phases

### Phase 0: event model and transport (no kernel events yet)

- Add `bpf/kernel_event.h`, `include/callgraph/kernel_event.h`.
- Add `KernelTimeline`, `StreamMerger`, `KernelReport` skeletons.
- Add `Output::emit_kernel`, `TraceParser` kernel regex, stats.
- Add CLI parsing for the new flags, but no BPF attachment; explicit
  `--events` reports "not implemented" or is hidden until Phase 1.
- Unit tests for format/parse/merger/state machine with synthetic events.

Acceptance: function-only output and all existing tests unchanged; synthetic
kernel events render and replay.

### Phase 1: scheduler

- Add `bpf/kernel/trace.bpf.c`, `sched.bpf.c`, maps, target filtering,
  `KernelProbeManager`.
- Attach `sched_switch`, `sched_wakeup`, `sched_waking`, `sched_wakeup_new`,
  `sched_migrate_task`, `sched_process_fork`, `sched_process_exit`.
- Implement the scheduler state machine and CPU/off-CPU/runqueue accounting.
- Add `--kernel`, `--sched`, `--merge-window`, and reuse `--ringbuf-size` for the
  kernel ring buffer.

Acceptance: a sleeping example yields correct off-CPU and runqueue values;
preemption is labeled runnable; function traces are unaffected when the flag
is absent.

### Phase 2: futex and I/O syscalls

- Add `syscall.bpf.c` macros for the P0 syscall set.
- Implement syscall enter/exit pairing and futex operation naming.
- Add blocking reason precedence.
- Add `--futex`, `--io`.

Acceptance: contended mutex and fsync examples produce paired intervals;
futex syscall duration is not double-counted with blocked time.

### Phase 3: block layer

- Add `block.bpf.c`, device filter, request correlation.
- Add `--block`, `--block-devices`.
- Report queue/device/total times with unmatched/reordered flags.

Acceptance: an fsync/write workload shows block request service time; a
missing insert is handled without dropping the completion.

### Phase 4: memory and network

- Add `mm.bpf.c`, `net.bpf.c`.
- Page-fault events, direct reclaim; socket syscalls, epoll/poll, opt-in TCP
  tracepoints.
- Add `--memory`, `--network`, global-event reporting.

Acceptance: page faults and direct reclaim are attributed; network syscall
waits are direct; TCP retransmits are global and clearly labeled.

### Phase 5: PMU

- Add `PerfCollector` counting and sampling.
- Map sample IPs to functions through the ELF resolver.
- Add `--pmu`, `--pmu-sampling`, permissions diagnostics.

Acceptance: counts match `perf stat` within tolerance; samples are labeled
approximate; denied access does not break other families.

### Phase 6: reports and OTel

- Add `Kernel:` summary, exclusive per-function attribution, unit selection.
- Add `SpanSink::on_kernel_event`, span events, attributes, caps.
- Add offline export parity and metadata.
- Consider per-root pairing and optional interval spans.

Acceptance: `--kernel --histogram --sched` preserves the tree/histogram pair and adds
a correct kernel summary; OTLP JSON validates and Jaeger shows span events.

## 14. File map

New:

```text
bpf/kernel_event.h                 shared 96-byte kernel record
bpf/kernel/trace.bpf.c             kernel BPF object entry
bpf/kernel/common.bpf.h            helpers and constants
bpf/kernel/maps.bpf.h              map definitions
bpf/kernel/sched.bpf.c             scheduler programs
bpf/kernel/syscall.bpf.c           futex/I/O/network syscall programs
bpf/kernel/block.bpf.c             block request programs
bpf/kernel/mm.bpf.c                page fault/reclaim programs
bpf/kernel/net.bpf.c               TCP/device programs
bpf/kernel/irq.bpf.c               later
include/callgraph/kernel_event.h   C++ record and enums
include/callgraph/kernel_timeline.h
include/callgraph/kernel_report.h
include/callgraph/event_merger.h
include/callgraph/kernel_probe_manager.h
include/callgraph/perf_collector.h
src/kernel_event.cpp               formatting/parsing helpers
src/kernel_timeline.cpp            state machine/accounting
src/kernel_report.cpp              summary rendering
src/event_merger.cpp               ordered merge
src/kernel_probe_manager.cpp       kernel object/maps/attachment
src/perf_collector.cpp             perf counting/sampling
```

Modified:

```text
CMakeLists.txt                     second BPF object and blob
src/main.cpp                       options, pipeline, shutdown, metadata
src/event_collector.cpp            drain/merge both streams
src/output.cpp/.h                  emit_kernel, drop policy
src/call_stack.cpp/.h              invocation/root IDs, active_frames
src/trace_parser.cpp/.h            kernel lines, stats
src/span_generator.cpp/.h          kernel span events/attributes
include/callgraph/span.h           SpanSink kernel callback
include/callgraph/trace_metadata.h kernel metadata
tests/unit/test_main.cpp           unit coverage
tests/integration.sh               root integration coverage
README.md, docs/design-notes.md    after implementation
```

## 15. Open questions

These need a decision before or during Phase 0/1:

1. Does the runtime tracepoint-offset map pass the verifier on the supported
   kernels? If not, choose the fallback (generated structs or BTF).
2. Is the 1 ms merge window sufficient on the target hardware, or should it
   be adaptive based on observed out-of-order records?
3. Should the kernel summary be per thread (MVP) or per root? Per-root needs
   a rule for intervals before/after the root.
4. Are block events global by default, or should `--block` require an
   explicit `--block-devices` filter on busy systems?
5. Does the brief fork over-capture window cause problems for `--children`
   off? If so, use userspace-only map updates and accept a thread blind spot.
6. Should PMU sampling use the kernel perf ring (recommended) or a BPF
   perf-event program with stack IDs in Phase 5?
7. How should PID-namespace TIDs be rendered in text: host TIDs (matching
   BPF) or namespace TIDs (matching the user's `ps`)?
8. Should `--system-wide` be allowed with `run`, or only with `attach`?
9. Do we need a raw-only mode that suppresses derived lines, or are the
   convenience durations harmless because replay recomputes them?
10. Should kernel text lines be emitted by default when a family is enabled,
    or only with `--report`? The design assumes raw lines are the
    default artifact.

## 16. P0 implementation notes

The first implementation deliberately narrows the full design:

- **Two BPF objects.** `bpf/trace.bpf.c` is untouched; `bpf/kernel/trace.bpf.c`
  is loaded only for `--sched/--futex/--io/--block`. Kernel records use a
  separate ring buffer, and `EventCollector` merges both streams by timestamp
  with a bounded reorder window.
- **Stateless BPF.** The kernel object only filters target TIDs and emits
  fixed 96-byte records. All scheduler/syscall/interval state is in
  `KernelTimeline`, so the same accounting path can later serve offline
  replay.
- **Runtime tracefs offsets.** `KernelProbeManager` parses the `format` file
  for each enabled tracepoint and fills a `tp_config` array map. BPF reads
  4- or 8-byte fields at those offsets; no `vmlinux.h` or per-kernel structs.
- **Target TIDs.** Userspace takes `/proc/<pid>/task` tids and also learns
  kernel-visible TIDs from function uprobe events. The latter is necessary
  when the userspace and BPF PID namespaces differ. A switch that happens
  before the first uprobe is unobserved, so the first interval is marked
  `partial=yes`.
- **Accounting.** `KernelTimeline` accounts at every function and kernel event
  boundary. Counters are aggregated by `(tid, depth, function_id)` rather than
  per invocation in the MVP; this bounds memory for long attach sessions.
  The report is per thread, not per root.
- **Families.** Scheduler (`switch`, `wakeup`, `waking`, `wakeup_new`,
  `migrate`, `fork`, `exit`), futex enter/exit, the read/write/pread/pwrite/
  fsync/fdatasync/openat/close/sync_file_range syscalls, and block
  insert/issue/complete/requeue/error. Block requests are correlated by
  `(dev, sector, nr_sector)` and report queue/device/total time.
- **Attribution.** Scheduler and syscall events are direct; block events are
  global. The timeline never charges a block completion to the running
  thread. The report prints `partial=yes` when the observed interval does not
  cover the whole story.
- **CLI.** Implemented: `--kernel` plus the secondary `--sched`, `--futex`,
  `--io`, `--block`, `--events`, `--preset`, `--report`, `--merge-window`,
  and `--require-events` options. `--ringbuf-size` sizes
  both the function and kernel ring buffers. `--children`, `--tid`, and
  `--system-wide` are not implemented yet.
- **Deferred.** Network, memory, PMU, IRQ/workqueue, per-root kernel reports,
  OTel span events for kernel records, and offline kernel-line replay. The
  text parser currently ignores `@CATEGORY` lines, so function-only export
  remains correct.
