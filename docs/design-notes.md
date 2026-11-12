# Design notes

This file records the decisions taken while implementing the design in
`README.md`, including deviations and open work.

## Confirmed choices

- Output markers are `->` (entry) and `<-` (return).
- The default module scope is the main executable only.
- Function filters are globs by default; `--regex` selects regex syntax.
- The old bpftrace prototype lives in `tools/legacy/`.

## Deviations from the original design

### Symbol source: symtab first, external debug as fallback

Entry points and names come from `.symtab` (`STT_FUNC` in executable
sections). `__cxa_demangle` handles C++ names, including clone suffixes such as
`foo.constprop.0`. If `.symtab` is absent, libdwfl locates external debug
information through the build ID or `.gnu_debuglink` and its symbol table is
used instead; `dwfl_report_offline` reports PIE modules at a synthetic base, so
the module bias is subtracted before computing uprobe offsets. Traversing
DWARF DIEs to recover symbol names (for debug files that contain no `.symtab`)
is still deferred; `--show-args` does walk subprogram DIEs, but only after symbols
have been resolved. Source file/line information is not collected yet.

### Vendored libbpf

The distro libbpf is 0.5.0 on Ubuntu 22.04, which predates
`bpf_program__attach_uprobe_multi`. libbpf v1.5.0 is vendored as a submodule
and built as a static library.

### BPF program sections

`uprobe_multi` programs must be declared as `SEC("uprobe.multi")` /
`SEC("uretprobe.multi")` so that libbpf sets
`expected_attach_type = BPF_TRACE_UPROBE_MULTI` at load time. A plain
`SEC("uprobe")` program will load but fail to attach.

### Return probes and C++ exceptions

The original design assumed that `uretprobe` only produces "missing returns"
for non-local control flow. In reality a `uretprobe` hijacks the return address
and points it at a trampoline with no `.eh_frame` metadata. If a C++ exception
unwinds through a traced function, the unwinder cannot continue and the
process calls `std::terminate`. This was confirmed with
`examples/exceptions.cpp`.

Two return modes are provided:

- `uretprobe` (default, matches the design): one probe per function, exact
  returns, unsafe for exception-based unwinding.
- `ret`: ordinary uprobes on disassembled `ret` instructions. No return
  address modification, so unwinding is safe. Frames unwound by an exception
  produce no return event and are later reported as `desync`.

The resolver warns when `.gcc_except_table` is present and `uretprobe` is
selected. `ret` mode requires libopcodes (`binutils-dev`) and is x86-only for
now.

### Filtering and depth

Filters are applied when probes are installed, not when events are printed.
Depth counts instrumented frames only. `--max-depth` is display-only so that
hidden frames still keep the remaining depths correct.

### Indentation

`--indent N` is display-only: it inserts `depth * N` spaces before the
demangled name, keeping the arrow column fixed. It does not affect filtering or
the reconstructed depth.

### Function arguments

`--show-args` appends entry-time parameter values to `->` lines. The BPF program
captures the six SysV x86-64 integer/pointer registers (`rdi`, `rsi`, `rdx`,
`rcx`, `r8`, `r9`) and six 64-bit words from the user stack at `rsp + 8`; the
event grows from 32 to 128 bytes. Exit events carry zeroed argument slots.

Parameter names, order, and types come from DWARF, resolved through libdwfl so
that build-id and `.gnu_debuglink` debug files work. Each parameter is placed
using the x86-64 SysV ABI: scalars consume a GP register, aggregates consume
one or two GP registers (or the stack), and floating-point values consume SSE
registers. The uprobe `pt_regs` context does not include XMM state, so
register-passed floats are shown as `?`; stack-spilled floats are decoded from
the captured stack words. Artificial parameters such as C++ `this` are used for
register allocation but omitted from the output. Aggregates are printed as raw
64-bit words, and pointers are not dereferenced.

The option is x86-64 only. Functions without DWARF, or whose DWARF type cannot
be classified, simply omit the suffix.

### Latency histogram

`--histogram` collects a per-thread latency distribution while the event stream
is consumed. On a matched return, `CallStack` derives the immediate caller from
the frame below the returning one (or a root sentinel at depth 0), subtracts the
entry timestamp, and adds the duration to the `(tid, parent, child)` edge. The
statistics live in a map separate from the live per-TID stacks, so erasing an
empty stack does not discard them. Frames skipped by a desync and frames still
live at shutdown have no measurable duration; they are counted as incomplete
instead.

The report is rendered after collection stops and appended to the event stream
by `Output::finish()`, which joins the writer thread first so the trailer cannot
overtake queued events. Nodes are keyed by an immediate caller edge, not by a
full call path, which keeps recursion and diamond-shaped call graphs bounded; a
DFS over the edge tree cuts off when a function is already on the current path
and marks that node `[recursive]`. Rendering uses `tree`-style connectors: each
node has a line prefix (`├── ` or `└── `) and a detail prefix (`│   ` or
`    `) of the same display width, so histogram lines align with the function
name while the vertical bars continue. Independent roots in one thread are
separated by a blank line. A frame that is still live at shutdown is kept as an
anchor (`calls=0  [incomplete]`) so completed calls made from inside it are
still rendered under the correct caller chain. Bucket `k >= 1` covers
`[2^(k-1), 2^k)` ns and bucket 0 is exactly 0 ns, so a 64-bit duration needs at
most 65 counters per edge. Units are chosen per node from its maximum latency.

`--max-depth` remains display-only and does not gate statistics. `--include` and
`--exclude` still filter at instrumentation time, so the reported tree is
compressed across excluded functions.

### Launch synchronization

`run` uses `fork` + `PTRACE_TRACEME` + `SIGSTOP`, then sets
`PTRACE_O_TRACEEXEC` and resumes. The child stops after `exec` but before the
dynamic loader runs; probes are attached, then the child is detached. The
pipe-before-exec alternative was not needed.

Shared libraries are not mapped at that point, so only the main executable is
traced from its first instruction. This matches the Phase 1 module scope.

### Event transport and ordering

Events go through `BPF_MAP_TYPE_RINGBUF`. The collector is single-threaded and
a dedicated writer thread drains a bounded line queue to stdout/file, so a
slow consumer does not immediately overflow the ring buffer. Ring-buffer
reservation failures are counted in a per-CPU array and reported at exit.

Per-thread event order is preserved because a thread's events are sequential;
cross-thread ordering is collector serialization order and should be analyzed
with timestamps.

### Timestamps

`bpf_ktime_get_ns()` is `CLOCK_MONOTONIC`, so the default output prints
seconds since boot with nine fractional digits (`85215.196474365`). It is not
a Unix epoch value. `-T` / `--wall-clock` samples
`CLOCK_REALTIME - CLOCK_MONOTONIC` at startup and prints local ISO 8601
timestamps (`2026-11-10T00:19:31.462805287+08:00`). NTP steps and suspend time
after startup are not corrected; seconds since boot is the stable form.

### Attach mode

Attach discovers the executable through `/proc/<pid>/exe`, attaches with the
target TGID (all threads), and polls a pidfd for target exit. Depth is relative
to the attach point: frames already on the stack before attachment are unknown.

### Attach failures and kernel-internal errno values

`uprobe_multi` registers every offset in one link, so a single offset that the
kernel cannot probe fails the whole batch. On x86 `uprobe_register()` rejects an
offset in `prepare_uprobe()`/`arch_uprobe_analyze_insn()` with `-ENOTSUPP`
(`524`) when the instruction is an `int3` byte, carries a segment or lock
prefix, masks exceptions (`cli`, `sti`, `popf`, `iret`, ...), or is otherwise
not in the kernel's whitelist of single-steppable opcodes. This is a per-offset
condition, not "multi-uprobe is unavailable"; the latter is `-EOPNOTSUPP`
(`95`) and triggers the individual-uprobe fallback.

For `-ENOTSUPP` the manager keeps bisecting the batch, so only the offending
offset is dropped and the remaining offsets stay in multi-uprobe links. A
single failing offset is reported with its path and file offset, and the run
continues. `524` is above the userspace errno range, so `strerror_r()` and
libbpf's `libbpf_strerror_r()` cannot name it; `errno_string()` maps the
kernel-internal codes and the libbpf print callback rewrites the opaque
`unknown error (-N)` fragments before they reach stderr.

### OTEL export

OTLP export is implemented as a second consumer of `CallStack` alongside the
text writer, and is shared by both `run` and `attach`. `SpanSink` receives
enter/exit callbacks from the existing stack reconstruction logic, so
recursion, desync matching, and shutdown handling are not duplicated. The
default trace scope is one trace per depth-0 root invocation;
`--trace-scope=thread` reuses a trace ID per TID. Attach-mode roots are marked
`callgraph.partial_stack=true` because their callers were already running when
tracing started.

Live spans use `ClockConverter` (realtime minus monotonic, sampled at startup
and recalibrated every 30 seconds) to convert `bpf_ktime_get_ns()` values to
Unix epoch nanoseconds. Offline text conversion converts timestamps in the
parser; boot-second logs require a `--trace-metadata` sidecar (preferred) or
`--assume-local-capture`. Desynced frames are closed at the return timestamp
that revealed the gap; frames live at shutdown are closed at the stop
timestamp. Both are marked `callgraph.incomplete=true` with an
`callgraph.end_reason` attribute rather than `status=ERROR`.

The exporter supports OTLP/gRPC (`--exporter otlp`, default port 4317) and
OTLP/HTTP with protobuf (`--exporter otlp-http`, default port 4318). OTLP
message definitions are vendored in `third_party/opentelemetry-proto` and
generated with `protoc`; the gRPC transport uses libcurl's HTTP/2 support with
gRPC framing. A build without protobuf can still use
`--exporter otlp-json --export-file FILE`. File export works without libcurl;
network export, batching, retries, custom headers, and gzip are compiled in
when libcurl is available. The exporter queue is bounded and never blocks the
ring-buffer collector. `--show-args` values are exported as one
`callgraph.arguments` string to avoid high-cardinality per-argument keys.

Root-trace sampling (`--sample-rate`) decides once per root and is inherited by
descendants so retained traces keep their full child tree. Source file/line
attributes come from DWARF; thread names come from
`/proc/<pid>/task/<tid>/comm` when the PID namespace permits it.

## Phase status

| Phase | Status |
|---|---|
| 0. spikes (uprobe_multi, ptrace launch, offsets) | done |
| 1. MVP: main exe, run/attach, filters, depth, output | done; `--show-args` added |
| 2. shared libraries, dlopen, module lifecycle | partial: `--all-modules`/`--module`, polling discovery; no perf-mmap events |
| 3. robustness: thread exit, desync policy, stripped+DWARF, batch failures | partial (desync, batch fallback, ring-loss, signals, external debug via libdwfl done; DIE-only debug files pending) |
| 4. statistics (`--summary`), JSON, source locations | partial: OTLP gRPC/HTTP export, source locations, and offline conversion done; aggregate summary pending |
| 5. performance, GDB comparison, CI | pending |

## Known limitations

- A stripped binary is only resolved if its external debug file also contains a
  symbol table (the usual `objcopy --only-keep-debug` output). DWARF-only debug
  files without `.symtab` are not traversed DIE by DIE yet.
- Modules are discovered by polling `/proc/<pid>/maps` (about every 100 ms).
  Calls in a library's constructors before the first poll are missed.
- `ret` mode is x86-only and requires libopcodes.
- `--show-args` is x86-64 SysV only. Register-passed floating-point arguments are
  unavailable because uprobe `pt_regs` has no XMM state, and pointers are not
  dereferenced.
- Child processes created with `fork` are not followed.
- `run` mode leaves the child's stdout connected to the same stream as the
  trace; use `-o` to separate them.
- Return values are not captured.
- No statistics or summary mode yet.
