# Stack-extent scoped shadow stacks

Status: **proposal, not implemented.** This document records a design for a
future change so it can be reviewed and refined before any code is written.

## Summary

Today the tracer keeps one shadow call stack per thread and assumes it
descends monotonically in memory. `longjmp`/`siglongjmp` repair relies on that
assumption (an entry below a recorded frame means the frames above it were
abandoned). Stackful runtimes violate it: `ucontext` and Boost.Context switch
to an unrelated stack, which the current heuristic mistakes for an unwind.

This design replaces the single per-thread frame vector with one shadow stack
per **stack extent**, and only applies the stack-pointer rule inside an
extent. A switch suspends the current extent instead of closing its frames.
`sigsetjmp`/`siglongjmp` within one stack keeps the existing bounded-depth
behaviour.

## Motivation

Measured behaviour with the current implementation:

| Case | Result |
| --- | --- |
| `ucontext`, one fiber, 5 000 switches | depth bounded, 1 `desync`, fiber frame lost |
| two fibers, B's stack **higher** than A's | false unwind: 2 `desync` + 2 `stray` |
| Boost.Context, `fiber_body` traced | 1 `desync`, fiber frame dropped |
| `siglongjmp` loop, default | error path at depths 1, 1, 1 |
| `siglongjmp` loop, `--no-rsp-resync` | depths 1, 9, 17 (regression) |

`--return-mode=ret` fixes lost return events across a switch, but not the
pruning: pruned frames then surface as `stray` returns.

## Constraint discovered during analysis

Adjacent stack mappings are merged by the kernel, so **one VMA is not one
stack**. Two 128 KiB `MAP_STACK` mappings:

```text
a=0x7545b9a8d000 b=0x7545b9a6d000
7545b9a6d000-7545b9aad000 rw-p 00000000 00:00 0     # one 256 KiB VMA
```

The same happened to a 1 MiB fiber stack allocated next to a pthread stack.
A design that identifies stacks purely by `/proc/<pid>/maps` therefore fails
for adjacent fibers.

## Goals and non-goals

Goals:

- A stack switch must not drop suspended frames.
- `sigsetjmp`/`siglongjmp` on one stack must keep bounded depth.
- No new flag for the common case; `--no-rsp-resync` keeps its meaning.

Non-goals:

- Joining a fiber to its resumer across a suspension. Resumption enters the
  fiber mid-function, so no entry event exists.
- Go goroutine identity.
- Coroutines that migrate between OS threads.

## Model

One shadow stack per stack extent. An extent is a logical stack, created on
the first observed entry on that stack and kept for the process lifetime.

```cpp
using ExtentId = uint32_t;              // 0 = unknown / single-extent mode

// Process-wide, because addresses are process-wide.
struct StackExtent {
    ExtentId id;
    uint64_t vma_start, vma_end;        // mapping that contained the first sp
    uint64_t top;                       // first observed sp, fixed at creation
    uint64_t min_sp, max_sp;            // observed sp range (historical)
    uint64_t last_active_seq = 0;       // LRU for exit fallback / eviction
};

// Per-TID.
struct ExtentState {
    std::vector<CallFrame> frames;
    uint32_t base_depth = 0;            // display depth of frames[0]
    uint64_t parent_token = 0;          // switch-site span
    uint64_t parent_function = kRootFunction;
};

struct ThreadState {
    std::unordered_map<ExtentId, ExtentState> extents;
    ExtentId current = 0;
};
```

Rules:

1. Pruning (`frames.back().sp <= new_sp`) is applied **only** inside the
   extent that owns `new_sp`.
2. Switching extents never closes frames. The suspended extent keeps its
   frames and its open spans.
3. `depth = base_depth + index_in_extent`.

## Extent identification

Layered, cheapest and most reliable signal first.

### 1. VMA lookup

Read `/proc/<pid>/maps`, keep a sorted vector of `[start, end)` ranges, and
binary-search `sp`.

- A different VMA means a different extent. This alone fixes the
  **main stack ↔ fiber stack** case, because the main stack is its own VMA,
  and any fibers allocated far apart.
- Refresh on miss (new fiber or thread) and at most every
  `kMapsRefreshInterval` (for example 100 ms); also refresh periodically
  (for example 1 s) for attach mode.

### 2. Extent range within a VMA

For a VMA that contains several extents, match `sp` against each extent's
historical `[min_sp, max_sp]`.

- Exactly one extent contains `sp`: that extent. This makes **resumes** exact,
  because a resumed fiber's `sp` is always inside its own historical range.
- `sp` is above every extent's `top` in the VMA: new extent with `top = sp`.
  This handles a switch to a **higher** stack inside a merged VMA.

### 3. Sound rule before any heuristic

Let `root.sp` be the sp of the outermost frame of the current extent.

- `sp > root.sp` means **switch**: no callee can enter above its caller, and
  every recorded frame is at or below the root. This is the exact rule for
  the false-unwind direction and needs no heuristic.
- `sp <= root.sp` and `sp` inside the current extent's range means the same
  extent; prune as today. This is the `longjmp` path.

### 4. Exact check for the ambiguous case

Ambiguous case: same VMA, `sp` below the current root, not inside any known
extent range. That is either a deep call on the current stack or a new
**lower** stack in a merged VMA.

Resolve it by **return-address ownership**:

1. Read `ra = *(uint64_t *)sp` with `process_vm_readv`. At function entry,
   `[sp]` holds the return address.
2. Resolve `ra` to a function and ask whether it falls in the runtime range
   of any function currently on the *current* extent's frame stack.
   - Yes: normal call or tail call on the same stack (a `longjmp` target is
     included, because the target is an ancestor).
   - No: switch. The return address belongs to another stack's caller (a
     fiber body, or the libc `makecontext`/signal trampoline).

Gate the check: only run it when `root.sp - sp > kVerifyThreshold` (for
example 8 KiB), so ordinary calls never pay for it. On read failure, fall
back to a distance heuristic and log at verbose level.

Function runtime ranges come from the module registry: `ModuleInfo` base plus
`FunctionInfo::low_pc/high_pc`, already resolved for probes. This needs a
small `FunctionRangeLookup` passed into `CallStack`; it is the only new
dependency.

Alternative that avoids `process_vm_readv`: capture `ra` in the BPF entry
event. That is one `bpf_probe_read_user` at `sp`, but it grows `cg_event`
from 136 to 144 bytes. Recommended only if the userspace read shows up in
profiles.

## Event change

Exit events must carry `sp` so returns can be routed:

```c
// bpf/trace.bpf.c, emit_event()
e->sp = entry_sp(ctx);      // for both ENTER and EXIT (was 0 for EXIT)
```

- `ret` mode: sp is the callee's frame, so the callee's extent.
- `uretprobe`: at the trampoline the return address is already popped, so sp
  is the caller's frame, which is the same extent for normal returns.
- Event size stays 136 bytes. Offline text traces keep `sp == 0` and use a
  single extent.

## Algorithms

### Entry

```text
extent = classify(sp)                    # above; 0 if disabled/offline
if extent == 0: extent = single_extent   # --no-rsp-resync, no pid, sp == 0

es = thread.extents[extent]
if es is new or es.frames empty:
    es.base_depth      = current_top_depth(thread) + 1   # 0 if no frames
    es.parent_token    = current_top_token(thread)
    es.parent_function = current_top_function(thread)

if extent == thread.current:
    prune(es.frames, sp)                 # existing rule, unchanged
# else: suspend the old extent, do not touch its frames

depth = es.base_depth + es.frames.size()
emit_enter(func, depth, parent = es.frames.empty() ? es.parent_token
                                                   : es.frames.back().span_token)
es.frames.push_back({func, ts, token, sp})
thread.current = extent
```

`base_depth` is fixed at the extent's first entry, so a fiber resumed from a
deeper or shallower point keeps a stable depth. Depth is bounded by the
number of live extents, not by the number of switches.

### Exit

```text
extent = classify(event.sp) if event.sp else thread.current
es = thread.extents[extent]
index = search es.frames for func_id
if not found:
    try thread.current, then other extents by last_active_seq   # cross-extent return
if still not found: ++stray_returns; return

depth = es.base_depth + index - 1
close_skipped_frames(es.frames, index)      # desync, within this extent only
emit_exit(...)
es.frames.pop_back()
if all extents empty: erase thread state    # NOT when only the current extent is empty
```

### Shutdown

- `finish_spans`: close every frame in every extent, innermost first.
- `finish_statistics`: `mark_incomplete` summed over extents; record one live
  stack per extent.

## Display, spans, histogram

| Surface | Decision |
| --- | --- |
| Text depth | `base_depth + index`; a fiber still prints nested under its switch site |
| `--max-depth` / `--indent` | unchanged, operate on the displayed depth |
| OTel parent | extent root's `parent_token` is the switch-site span, so the trace tree stays connected |
| OTel attribute | extent root gets `callgraph.partial_stack=true` (its caller chain is unobservable); optional extra `callgraph.context_switch=true` |
| Trace scope `root` | a root is a frame with no parent; a fiber root has a parent, so it stays in the same trace |
| Sampling | inherited through `parent_token`, unchanged |
| Histogram tree | extent roots are rendered as roots (`kRootFunction`), because a switch is not a call; `parent_function` is used only for the live-chain anchor |
| `live_stacks` | `ThreadLatency` gains `std::vector<std::vector<uint64_t>>` so suspended extents are not lost |

The `partial_stack` flag needs one new boolean on
`SpanSink::on_function_enter` (or a `SpanRecord` field set by `CallStack`);
`SpanGenerator` and `FlameGraphSink` both need the trivial update.

## Interaction matrix

| Case | Result |
| --- | --- |
| `longjmp`/`siglongjmp` on one stack | unchanged: same extent, prune still bounds depth |
| `siglongjmp` out of an altstack handler | altstack extent is suspended and never resumed; its frames close at shutdown. New, documented limitation |
| `sigaltstack` handler | separate extent; `base_depth` nests it under the interrupted frame |
| `ucontext` / Boost.Context | correct extents; no `desync`; returns route by `sp` |
| Two adjacent fibers in one VMA | resolved by rules 2–4; exact when the return-address check is enabled |
| Threads | extents are process-wide, frames per TID; no change |
| `--no-rsp-resync` | disables classification **and** pruning: one extent, current behaviour |
| Offline `export --otel/--flame` | `sp == 0` means one extent, unchanged |
| Attach mode | first observed sp may not be the true top; documented, `partial_stack` already set |
| Go | relocation creates a new VMA and would create a new extent, growing depth. Keep `--no-rsp-resync` as the Go recommendation; real support needs `g` identity |

## Performance and limits

- `classify`: one binary search plus a hash lookup per entry, about 1 µs
  worst case.
- Maps refresh: only on miss, rate-limited; periodic refresh for attach.
- Return-address check: only past the 8 KiB threshold,
  `process_vm_readv` about 1–2 µs.
- Extents are never freed because tops are unique. Cap at `kMaxExtents`
  (for example 4096) with LRU eviction of extents that have no live frames,
  and warn when the cap is hit.

## Testing plan

Unit tests (`tests/unit/test_main.cpp`, with an injected deterministic
classifier):

1. Higher-stack switch: 0 `desync`, both extents retained, base depths 1 and 3.
2. Lower-stack switch in one VMA: 0 `desync`, distinct extents.
3. `longjmp` within an extent: still prunes (depths 1, 1, 1).
4. Resume: frames restored, `parent_token` unchanged.
5. Exit routed by `sp`; exit with `sp == 0` falls back to current.
6. Shutdown closes all extents; thread state is not erased while another
   extent is live.
7. `set_rsp_resync(false)` means a single extent and the old behaviour.

Integration tests:

- `examples/ucontext.cpp`: default now reports 0 `desync` and `<- fiber_body()`.
- Two fibers with forced addresses (the `uctx_two` reproducer): 0 `desync`,
  0 `stray`.
- Boost.Context with `fiber_body` traced.
- `sigaltstack` handler: nested depth.
- Existing `longjmp` test must keep depths 1, 1, 1.
- Go 300-deep with `--no-rsp-resync`: depth 303, unchanged.
- Attach mode smoke test.

## Rollout

1. Phase A: exit `sp`, extent table, VMA/range/root rules (sections 1–3),
   per-extent frames, depth/span/histogram changes, tests.
2. Phase B: return-address verification (section 4) for merged-VMA ambiguity.
3. Phase C (separate): goroutine identity for Go.

`--no-rsp-resync` remains the escape hatch and means "one extent, return
matching".

## Alternatives rejected

- **VMA-only regions**: rejected; adjacent stacks merge (see the constraint
  section).
- **Distance-threshold-only clustering**: unsound for large frames; kept only
  as a fallback when the return-address read fails.
- **Instrumenting `swapcontext`/`jump_fcontext`**: precise, but couples the
  tracer to glibc/Boost internals and misses custom switches.
- **BPF-captured return address**: clean, but bumps the event to 144 bytes;
  deferred.

## Open questions

1. `partial_stack` versus a new `context_switch` attribute on extent roots.
2. Histogram extent roots: separate roots (proposed) versus parented under
   the switch site.
3. Whether to raise an extent's `top` in attach mode to avoid a spurious
   split.
4. Extent eviction policy and cap.
