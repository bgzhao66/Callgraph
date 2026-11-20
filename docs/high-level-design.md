# callgraph — High-Level Design

This document describes the architecture of the current implementation: what the
system is for, how its layers fit together, how data flows end to end, and which
tradeoffs shaped it. It is deliberately top-down; detailed behavior lives in the
topic-specific documents listed at the end.

## 1. Purpose

`callgraph` answers “where did the time go?” for native Linux executables
**without recompiling, relinking, or adding instrumentation**.

It attaches eBPF uprobes to function entry and return points, reconstructs a
separate call tree per thread, optionally correlates kernel waits and hardware
events with the user frame that was running, and emits one of several
presentations: text, latency histograms, folded stacks, or OTLP spans.

The system is built around one reconstruction core (`CallStack` +
`KernelTimeline` + `SpanGenerator`) shared by live tracing and offline replay.
Front ends and exporters are replaceable around that core.

## 2. Goals and non-goals

### Goals

- **Observe unmodified binaries.** Symbols come from `.symtab` or separate debug
  info found by build ID or `.gnu_debuglink`.
- **Reconstruct real per-thread stacks.** Handle recursion, multiple threads,
  `longjmp`, C++ exceptions, tail calls, and late-loaded shared libraries.
- **Keep overhead bounded and predictable.** Prune probes statically, limit
  depth structurally, batch attachment, sample, rate-limit, and drop rather
  than block.
- **Separate observation from presentation.** The same event stream feeds text,
  histograms, flamegraphs, and OTLP.
- **Be safe on real processes.** Avoid `uretprobe` unwinding hazards for
  exception-heavy code; require no kernel BTF or kernel headers.
- **Make kernel context first-class.** Attribute scheduler, futex, I/O,
  reclaim, page-fault, network, and PMU activity to the user frame that was
  running.

### Non-goals

- It is **not a sampling profiler**: only instrumented functions are observed.
- No source changes, compiler plugins, or runtime hooks.
- No inlined-frame reconstruction from DWARF.
- No goroutine-level (Go) or fiber-level identity; stackful runtimes are
  supported only to a documented approximation.
- No Windows/macOS support, no kernel module, no offline kernel-line replay.
- `callgraph-disasm` is deliberately **not** a second tracer or a shared
  library.

## 3. System context

```text
        ┌────────────┐
        │  Operator  │
        └─────┬──────┘
              │ CLI
┌─────────────▼──────────────┐        ┌──────────────────────┐
│ callgraph-run / attach     │───────▶│  Target process      │
│ callgraph-export / disasm  │ uprobe │  (unmodified ELF)    │
│ callgraph wrapper          │◀───────│                      │
└─────────────┬──────────────┘ events └──────────────────────┘
              │
              │ tracepoints / perf_event_open
┌─────────────▼──────────────┐
│ Linux kernel               │
│ uprobes, tracefs, perf     │
└─────────────┬──────────────┘
              │
              ▼
     text / histogram / folded stacks / OTLP
              │
              ▼
     files or OTLP backend (e.g. Jaeger)
```

The target is treated as a black box. The only requirements are a symbol table
(or separate debug info), permission to install uprobes, and—for PMU—permission
to open perf events.

## 4. Architecture at a glance

The implementation is a five-layer pipeline. Each layer depends only on the one
below it.

```text
┌─────────────────────────────────────────────────────────────┐
│ 1. Front ends                                               │
│    callgraph-run · callgraph-attach · callgraph-export      │
│    callgraph-disasm · callgraph wrapper (MIT)               │
├─────────────────────────────────────────────────────────────┤
│ 2. Session orchestration                                    │
│    argument parsing · validation · module discovery         │
│    probe selection · child lifecycle · signal handling      │
├─────────────────────────────────────────────────────────────┤
│ 3. Collection                                               │
│    function uprobes (BPF) · kernel tracepoints (BPF)        │
│    perf events (PMU) · ring buffers · timestamp merger      │
├─────────────────────────────────────────────────────────────┤
│ 4. Reconstruction and attribution                           │
│    CallStack (per TID) · KernelTimeline · SpanGenerator     │
├─────────────────────────────────────────────────────────────┤
│ 5. Presentation and export                                  │
│    Output (text) · histogram report · flamegraph            │
│    OtelExporter (OTLP/gRPC, HTTP, JSON) · static renderer   │
└─────────────────────────────────────────────────────────────┘
```

### Why the layers are split this way

- **Collection is stateless.** BPF emits fixed-layout records and performs no
  symbol resolution or stack reconstruction.
- **Reconstruction is presentation-agnostic.** `CallStack` owns nesting and
  pairing; `SpanGenerator` is one sink among several.
- **Export cannot break tracing.** The text path works with no network, no
  protobuf, and no libcurl.
- **Licensing boundaries are physical.** The tracer never links `libopcodes`;
  `callgraph-disasm` is a standalone GPL program that emits JSON facts.

## 5. Component responsibilities

| Component | Layer | Responsibility |
|---|---|---|
| `callgraph` wrapper | Front end | Parses wrapper options, decides whether facts are needed, runs `callgraph-disasm`, invokes the tracer with `--static-graph`, cleans up temporary facts. Contains no analysis logic. |
| `main_run` / `main_attach` / `main_export` | Front end | Thin entry points selecting `ProgramMode` and calling the shared session. |
| `parse_trace_args` / `cli_common` | Session | One CLI grammar per mode, validation, help, diagnostics. |
| `ProcessController` | Session | Launch, stop, detach, and observe the target process. |
| `ModuleManager` | Session | Discovers mapped ELF modules via `/proc/<pid>/maps`; supports late loading. |
| `ElfResolver` | Session | Resolves symbols, build IDs, debug links, DWARF signatures and source locations. |
| `ProbeManager` | Collection | Owns the function BPF object and uprobe/uretprobe links; `uprobe_multi` with individual fallback. |
| `KernelProbeManager` | Collection | Owns the separate kernel BPF object and tracepoint links; learns target TIDs. |
| `PerfCollector` | Collection | Opens per-thread perf groups and sampling rings; handles PMU permissions and multiplexing. |
| `EventCollector` | Collection | Polls function, kernel, and perf rings; reorders by timestamp; dispatches events. |
| `CallStack` | Reconstruction | Maintains one frame stack per TID; pairs entries/returns; handles recursion, desync, `rsp` resync, depth limits, and sampling gates. |
| `KernelTimeline` | Reconstruction | Reconstructs per-TID kernel intervals and attributes them to the current user frame. |
| `SpanGenerator` | Reconstruction | Converts closed frames and kernel events into OTel spans; handles trace scope, sampling, outlier tail sampling, and complete-trace buffering. |
| `Output` | Presentation | Serializes text lines on a dedicated writer thread with bounded queues and rate limiting. |
| `OtelExporter` | Presentation | Batches, encodes, retries, and transports spans; tracks drop reasons. |
| `TraceParser` | Offline | Replays text traces through the same `CallStack` path. |
| `static_*` / `callgraph-disasm` | Static analysis | Collects ELF and disassembly facts, prunes direct calls, and renders static trees. |

## 6. End-to-end flows

### 6.1 Live text tracing

```text
parse args → launch/attach → resolve modules → select functions
→ attach uprobes → collect events → CallStack → Output → text
```

1. The CLI validates options and resolves the target executable.
2. Modules are discovered and symbols resolved; filters and depth rules select
   functions.
3. `ProbeManager` batches uprobes; `KernelProbeManager` attaches tracepoints if
   requested.
4. `EventCollector` drains rings and merges events by timestamp.
5. `CallStack` reconstructs nesting and emits lines through `Output`.
6. On shutdown, histograms and PMU totals are appended after queued lines are
   flushed.

### 6.2 Live OTel export

The same reconstruction path runs, but `CallStack` receives a `SpanSink`.
Closed frames become spans, `SpanGenerator` applies trace scope and sampling,
and `OtelExporter` batches and sends them. Text output remains independent and
can run alongside export.

### 6.3 Offline conversion

```text
text trace → TraceParser → CallStack → SpanGenerator → OTel / flamegraph
```

The parser uses the text depth column to close frames at or above each entry’s
depth, so replay produces the same tree shape without live `rsp` values.

### 6.4 Static facts and rendering

```text
ELF module(s) → callgraph-disasm → facts JSON → callgraph-export --static → tree
                              └────▶ --static-graph → tracer pruning / ret offsets
```

Facts carry functions, direct edges, flags, default roots, and return offsets.
Modules are joined by build ID, then canonical path, then function `low_pc`.

## 7. Core mechanisms

### 7.1 Probe selection and static pruning

- `--root-scope` selects functions that may start a tree; the outermost match
  per thread becomes depth 0.
- `--exclude` removes a node and splices its descendants.
- `--trace-depth N` is structural. For `N > 0`, probes are pruned along
  **resolved direct calls and unconditional jumps only**. Indirect call sites
  add no targets.
- Omitting `--trace-depth` is conservative: every non-excluded function,
  including possible indirect callees, is instrumented.
- If analysis is unavailable, the tracer does not silently instrument
  everything. It warns and uses only explicit roots.

This is a deliberate predictability tradeoff: the tool never guesses an
indirect target.

### 7.2 Event transport and ordering

- Function events are fixed-size records containing timestamp, function cookie,
  TGID/TID, type, entry `rsp`, and captured arguments.
- Kernel events use a separate layout and a separate BPF object so a
  kernel-tracing failure cannot break the function tracer.
- PMU samples arrive through perf rings and are merged into the same timestamp
  stream.
- A configurable merge window (default 1 ms) reorders events from independent
  sources before attribution.

### 7.3 Call-stack reconstruction

`CallStack` is the correctness core:

- One shadow stack per TID.
- Entries push; returns pop and close spans.
- Recursion is preserved as repeated frames.
- Entry `rsp` detects frames abandoned by `longjmp`, exceptions, or tail calls:
  a new entry at a shallower-or-equal stack pointer closes frames that cannot
  be ancestors.
- `--no-rsp-resync` disables that heuristic for stackful runtimes.
- `--return-mode=ret` replaces return probes with uprobes on `ret`
  instructions, avoiding unwinder breakage in C++ exception paths.
- Offline replay uses the depth column instead of `rsp`.

### 7.4 Kernel correlation

`KernelTimeline` tracks per-TID kernel state and attributes intervals to the
innermost open user frame:

- **Intervals:** syscall enter/exit, direct reclaim, scheduler off-CPU and
  runqueue.
- **Points:** page faults, wakeups, migrations, fork, exit.
- **Global, text-only:** block requests and TCP retransmits.
- Kernel spans become children of the innermost open kernel or user span.

Kernel families are selected by presets and explicit flags. Block and PMU are
opt-in: no preset enables them.

### 7.5 PMU counting and sampling

- Counting opens one `PERF_FORMAT_GROUP` per thread with enabled/running times.
- Sampling opens one ring per counter per thread and attributes each sampled IP
  to the innermost active traced frame.
- Events are opened disabled and enabled after the ptrace stop window, so
  enabled time is meaningful.
- PMU-only runs do not load the kernel BPF object.
- Unavailability warns and continues unless `--require-events` is set.

### 7.6 Span mapping

`SpanGenerator` maps reconstructed frames to OTel spans:

- One trace per depth-0 root by default; thread and process scopes are
  available.
- Sampling is decided once per root and inherited by descendants.
- Outlier tail sampling exports traces above a duration quantile in addition to
  the baseline sample.
- `--complete-traces` buffers a whole trace until all spans close and a root
  exists, then exports root-first.
- Source file/line, module/build ID, thread name, arguments, and kernel
  attributes are attached when available.

## 8. Data model

| Concept | Representation |
|---|---|
| Function event | Fixed BPF record: timestamp, cookie, TGID/TID, enter/exit, `rsp`, captured args. |
| Call frame | Function ID, start timestamp, span token, entry `sp`, sampling flags. |
| Call path | Root-first sequence of function names, used for histograms and flamegraphs. |
| Kernel interval | TID, kind, start/end, attributes, owning user depth. |
| Span | Trace/span IDs, parent, name, timestamps, attributes, status. |
| Static facts | Versioned JSON: modules, functions, flags, direct edges, roots, `ret` offsets. |

## 9. Concurrency and lifecycle

```text
Main thread
  parse → resolve → attach → detach child → start perf → run collector

Collector thread
  poll/epoll rings → merge by timestamp → CallStack / KernelTimeline / SpanGenerator

Output writer thread
  bounded queue → stdout or file; drops and counts under backpressure

Exporter worker
  bounded queue → batch → encode → send; tracks drop reasons
```

- Signals set a stop flag; the collector exits its poll loop and the session
  finishes deterministically.
- A child guard kills a launched target if setup fails before tracing starts.
- Perf events are enabled only after the child is detached from ptrace.
- Shutdown order flushes the writer before appending histograms so the trailer
  cannot overtake queued events.

## 10. Performance and overhead strategy

- `uprobe_multi` batches attachment; individual uprobes are a fallback.
- Static pruning and `--trace-depth` reduce the number of installed probes.
- Root-scope filtering happens at attach time, not print time.
- Ring buffers are sized explicitly; the collector drops and counts malformed
  events.
- `--ingest-sample-rate` gates tracing at root entry without disturbing stack
  tracking.
- `--log-rate-limit` limits stdout lines with independent user/kernel token
  buckets.
- `--sample-rate` and outlier tail sampling reduce export volume.
- `--max-depth` and `--indent` are display-only and never change
  reconstruction.
- PMU counting is per-thread and opt-in; sampling uses a configurable period.

## 11. Failure handling and correctness boundaries

**Handled explicitly:**

- Lost returns and non-local jumps (`rsp` resync, desync accounting).
- C++ exceptions in return-probe mode (warn, or use `ret` mode).
- Stripped binaries without separate debug info (clear rejection).
- Late-loaded shared libraries (periodic `/proc` rescan).
- Missing kernel tracepoints or PMU counters (warn or fail with
  `--require-events`).
- Exporter backpressure (bounded queues, drop reasons, optional fail-fast).
- Trace-buffer overflow with `--complete-traces` (whole trace dropped as
  `trace-buffer-overflow`).

**Known boundaries:**

- Go goroutines and stackful fibers are not tracked by identity; nesting across
  a switch is approximate.
- `--show-args` live capture is x86-64 SysV only and cannot show register-passed
  floats.
- Static pruning ignores indirect calls by design.
- Block events and TCP retransmits are global and text-only.
- Kernel-event attribution is per TID, not per task hierarchy.

## 12. Build, packaging, and licensing

- Linux-only, C++20, CMake 3.20+.
- Two BPF objects are compiled with clang and embedded into the binaries at
  build time.
- Vendored libbpf provides `uprobe_multi` support.
- Five artifacts: `callgraph-run`, `callgraph-attach`, `callgraph-export`,
  `callgraph-disasm`, and the `callgraph` wrapper.
- The three tracer/exporter programs are AGPL-3.0-only or commercially
  licensed.
- `callgraph-disasm` is GPL-3.0-only because it links `libopcodes`; the tracer
  never does.
- The wrapper is MIT and contains no analysis logic.

## 13. Extension points

| Extension | Where to add it |
|---|---|
| New kernel event family | `bpf/kernel/`, `KernelProbeManager`, `KernelTimeline`, `KernelSelection`, help/presets. |
| New exporter or protocol | Implement a `SpanSink` consumer; keep `SpanGenerator` unchanged. |
| New presentation | Consume `CallStack`/`KernelTimeline` output; do not add stack logic. |
| New static-analysis consumer | Extend the versioned facts schema and the JSON reader. |
| New PMU counter or alias | `pmu.cpp` table and parser; help intentionally lists only common counters. |

## 14. Key design tradeoffs

| Decision | Benefit | Cost |
|---|---|---|
| Uprobes instead of sampling | Exact call trees and per-call latency | Higher overhead on very hot functions; requires symbols |
| Direct-call-only pruning | Predictable instrumentation | Indirect callees are missed unless depth is unlimited |
| Per-TID shadow stacks | Simple, fast reconstruction | No goroutine/fiber identity |
| `rsp` resynchronisation | Bounded depth after `longjmp` | Assumes one stack per thread; stackful runtimes need opt-out |
| Separate kernel BPF object | Kernel tracing cannot break function tracing | Two objects to build and load |
| Text-first core with OTel sinks | Works offline and without protobuf/curl | Two representations to keep consistent |
| Drop rather than block | Tracing cannot stall the target | Lossy output under extreme volume, reported explicitly |
| Standalone GPL disassembler | Keeps tracer license clean | Facts must cross a JSON boundary |

## 15. Document map

- `README.md` — user-facing overview, CLI, examples, requirements.
- `docs/design-notes.md` — implementation decisions and deviations, including
  `rsp` resync and runtime caveats.
- `docs/kernel-event-design.md` — kernel event families, presets, PMU,
  attribution model.
- `docs/otel-export-design.md` — span mapping, trace scope, sampling, exporter
  behavior.
- `docs/static-graph-format.md` — versioned facts schema.
- `docs/stack-region-design.md` — future per-stack-region tracking.
- `AGENTS.md` — repository conventions and the enforced CLI contract.
