# callgraph

A Linux function call-graph tracer for native executables, built on libbpf and
eBPF uprobes. It resolves function names from ELF symbol tables or external
debug information, attaches one entry probe per function, reconstructs a
separate call stack for every thread, and writes a single chronological event
stream.

```
<ts> <tid> : <depth> -> function
<ts> <tid> : <depth> <- function
```

## Status

The current implementation includes:

- launch (`run`) and attach (`attach -p PID`) modes
- symbol resolution from ELF `.symtab`, or from external debug information via
  libdwfl (build-id / `.gnu_debuglink`), with C++ demangling
- optional mapped-module tracing (`--all-modules`, `--module GLOB`), including
  modules loaded after startup (discovered by polling `/proc/<pid>/maps`)
- `uprobe_multi` attachment with per-function cookies and individual-uprobe fallback
- entry and return events over a BPF ring buffer
- per-TID call-stack reconstruction, recursion, multi-threaded tracing
- include/exclude filters, maximum displayed depth, dry-run listing
- optional function argument values from DWARF (`--show-args`, x86-64)
- two return-probe modes: `uretprobe` (default) and `ret` (exception-safe)
- OTLP export for Jaeger: gRPC (`--exporter otlp`), OTLP/HTTP with
  protobuf (`--exporter otlp-http`), OTLP/JSON file output
  (`--exporter otlp-json`), and `callgraph export --otel` for existing text
  traces
- folded-stack flamegraph export via `callgraph export --flame`
- root-trace sampling, source file/line attributes, and best-effort thread
  names

Not implemented yet: a `--summary` aggregated statistics mode and
child-process (`fork`) following.

## Requirements

| Component | Needed for |
|---|---|
| Linux 6.6+ | `uprobe_multi` (older kernels fall back to individual uprobes) |
| C++20 compiler, CMake 3.20+ | host build |
| clang with the BPF target | compiling `bpf/trace.bpf.c` |
| libelf, libdw, zlib | ELF symbols, external debug info, compression |
| libcurl (optional) | OTLP network export; `--exporter otlp-json` works without it |
| protobuf + protoc (optional) | OTLP gRPC and OTLP/HTTP protobuf; JSON file export works without it |
| DWARF debug info (`-g` or a separate debug file) | `--show-args` parameter names and types; source file/line attributes |
| x86-64 | `--show-args` value capture (SysV ABI) |
| `binutils-dev` (libopcodes) | optional; enables `--return-mode=ret` |
| root or `CAP_BPF`+`CAP_PERFMON`+`CAP_SYS_ADMIN` | uprobes |
| ptrace permission | attach mode |

The target must still have its `.symtab` (do not `strip` it), or a separate
debug file discoverable by build-id or `.gnu_debuglink` (for example the output
of `objcopy --only-keep-debug`). Debug info is not required for symbol names. The tool does **not** need kernel BTF or kernel
headers: the BPF program uses only helpers and its own event layout.

## Build

The repository vendors libbpf as a submodule (the distro package may be too old
for `uprobe_multi`):

```bash
git submodule update --init --recursive
cmake -S . -B build -DCMAKE_BUILD_TYPE=RelWithDebInfo
cmake --build build -j
```

The binary is `build/callgraph`.

On Debian/Ubuntu, Fedora/RHEL/CentOS, Arch, or openSUSE, the dependency
installer handles the system packages and initializes the libbpf submodule:

```bash
./tools/install-deps.sh              # required + optional feature packages
./tools/install-deps.sh --minimal    # required packages only
./tools/install-deps.sh --dry-run    # print commands without changing the system
```

It checks for CMake 3.20+, a C++20 compiler, clang with the BPF target,
pkg-config, libelf, and libdw. If the distro's CMake is older than 3.20, it
prints an actionable error instead of building with a broken toolchain.

OTLP network export needs `libcurl` development headers. OTLP/gRPC and
OTLP/HTTP-protobuf additionally need `protobuf-compiler` and the protobuf C++
development headers. Without protobuf, `--exporter otlp-json` still writes OTLP/JSON.

## Usage

```bash
# Launch and trace from the first instruction
sudo ./build/callgraph run -- ./my_app arg1 arg2

# Wall-clock timestamps instead of seconds since boot
sudo ./build/callgraph run -T -- ./my_app

# Indent names by depth (two spaces per level)
sudo ./build/callgraph run --indent 2 -- ./my_app

# Show argument values after names (requires DWARF debug info)
sudo ./build/callgraph run --show-args -- ./my_app

# Attach to a running process
sudo ./build/callgraph attach -p 12345

# List resolved functions without attaching
./build/callgraph run --dry-run -- ./my_app

# Only your code, with full regex syntax
sudo ./build/callgraph attach -p 12345 --regex \
    --include '^(main|Database::)' --exclude 'Database::Debug'

# Exception-using C++ program: avoid uretprobe unwinding breakage
sudo ./build/callgraph run --return-mode ret -- ./my_app

# Redirect the event stream to a file (keeps the app's stdout separate)
sudo ./build/callgraph run -o trace.log -- ./my_app

# Export to a Jaeger OTLP receiver over gRPC (default localhost:4317)
sudo ./build/callgraph run -T --exporter otlp -- ./my_app

# Export over OTLP/HTTP with protobuf (default http://localhost:4318)
sudo ./build/callgraph run -T --exporter otlp-http -- ./my_app

# Write an OTLP/JSON request body that can be POSTed later
sudo ./build/callgraph run -T --exporter otlp-json \
    --export-file trace.otlp.json -- ./my_app

# Convert an existing text trace (use -T, --metadata, or --assume-local-capture)
./build/callgraph export --otel \
    --input trace.log --output spans.json --service-name my_app

# Export folded stacks for flamegraph.pl / inferno-flamegraph
./build/callgraph export --flame \
    --input trace.log --output stacks.folded
```

### Options

```
Usage:
  callgraph run [options] -- program [args...]
  callgraph attach [options] -p PID
  callgraph export --otel|--flame [options] --input TRACE

  -o, --output FILE     write events to FILE (default: stdout)
      --include GLOB    only trace functions matching GLOB (repeatable)
      --exclude GLOB    skip functions matching GLOB (repeatable)
      --regex           treat --include/--exclude as extended regex
      --return-mode M   uretprobe (default) or ret (exception-safe)
      --all-modules     trace every mapped ELF module
      --module GLOB     also trace mapped modules matching GLOB
  -T, --wall-clock      wall-clock timestamps (default: seconds since boot)
      --max-depth N     print events with depth <= N (default: unlimited)
      --indent N        indent names by depth*N spaces (default: 0)
      --show-args       show function arguments after names (needs DWARF)
      --histogram       append a per-thread call tree and latency histograms to the output
      --probe-batch-size N  functions per uprobe_multi link (default: 1000)
      --ringbuf-size N  ring buffer size, k/m/g suffix (default: 16m)
      --dry-run         list resolved functions and exit
      --exporter M      stdout (default), otlp, otlp-http, or otlp-json
      --endpoint URL    OTLP endpoint; default localhost:4317 / :4318
      --export-file FILE  output file for --exporter otlp-json
      --service-name NAME
                        override service.name (default: exe basename)
      --service-namespace NAME
      --trace-scope M   root (default), thread, or process
      --batch-size N    spans per OTLP batch (default: 512)
      --batch-bytes N   OTLP request size limit (default: 1m)
      --flush-interval N  OTLP batch flush interval in ms (default: 1000)
      --timeout-ms N    OTLP HTTP timeout (default: 5000)
      --queue-spans N   exporter queue limit (default: 10000)
      --header K=V      add an HTTP header (repeatable)
      --compression M   none (default) or gzip (OTLP/HTTP only)
      --sample-rate R   root-trace sampling rate, 0..1 (default: 1)
      --fail-on-export-error  exit non-zero if export fails
      --trace-metadata FILE  write an offline-conversion sidecar
  -v, --verbose         verbose diagnostics
  -h, --help            show help
      --version         show version
```

`callgraph export --otel` accepts `--input TRACE`, `--output FILE`,
`--endpoint URL`, `--service-name NAME`, `--service-namespace NAME`,
`--metadata FILE`, `--assume-local-capture`, `--trace-scope MODE`,
`--trace-id-seed HEX`, `--sample-rate R`, `--input-show-args`, and batch/HTTP
options (`--batch-size`, `--batch-bytes`, `--flush-interval`, `--timeout-ms`,
`--queue-spans`, `--compression`, `--header`, `--fail-on-export-error`).

`callgraph export --flame` accepts `--input TRACE` and optional
`--output FILE`; it writes folded stacks to stdout by default. The two modes
are mutually exclusive.

Filters are matched separately against the demangled name and the mangled
symbol name, so anchored patterns such as `^main$` work. Glob is the default;
`--regex` switches to C++ `std::regex` (ECMAScript) syntax. Include wins over
the default "everything"; exclude then removes matches.

The main executable is always considered. `--all-modules` adds every mapped
ELF file that has a usable symbol table; `--module GLOB` adds matching mapped
modules (the glob is tried against both the full path and the basename).
Modules loaded after tracing starts (shared libraries, `dlopen`) are discovered
by polling `/proc/<pid>/maps` roughly every 100 ms. Calls made before the new
module is attached (for example, early constructors) are not seen.

## Output

Each event is one complete line:

```
<ts> <tid> : <depth> -> <demangled name>
<ts> <tid> : <depth> <- <demangled name>
```

Example (`examples/simple.cpp`, filtered to `main`, `A`, `B`, `C`):

```
85215.196474365 26570 : 0 -> main
85215.196489646 26570 : 1 -> C(int)
85215.196498980 26570 : 1 <- C(int)
85215.196522041 26570 : 0 <- main
```

- `ts` is seconds since boot (`CLOCK_MONOTONIC`, nine fractional digits) by
  default. It is not an epoch timestamp.
- With `-T` / `--wall-clock`, `ts` is local wall-clock time in ISO 8601, for
  example `2026-11-10T00:19:31.462805287+08:00`.
- `--indent N` inserts `depth * N` spaces before the name, leaving the arrow
  column fixed.
- `tid` is the Linux thread ID; all threads share the same stream.
- `depth` is maintained independently per TID.
- Entry events print the stack size *before* pushing the frame.
- Return events print the depth of the matched frame *before* popping it.

With `--indent 2`:

```
85215.196474365 26570 : 0 -> main
85215.196489646 26570 : 1 ->   C(int)
85215.196498980 26570 : 2 ->     B(int)
85215.196522041 26570 : 1 <-   C(int)
```

With `--show-args`, entry events append the captured parameter values:

```
85215.196474365 26570 : 0 -> main
85215.196489646 26570 : 1 -> C(int) [x=3]
85215.196498980 26570 : 1 <- C(int)
85215.196522041 26570 : 0 <- main
```

Arguments are shown only on `->` lines. Parameter names and types come from
DWARF, so the target must be compiled with `-g` (or have separate debug info).
The values are captured at function entry. Return events do not repeat them.

Limitations:

- `--show-args` currently supports the x86-64 SysV ABI only.
- Floating-point arguments passed in XMM registers are printed as `?`, because
  the uprobe `pt_regs` context does not contain XMM state. Stack-passed
  `float`/`double` values can still be decoded.
- Aggregates are printed as raw 64-bit words (`{0x..., 0x...}`); aggregates
  containing floating-point fields are printed as `?`.
- Pointers are printed as hexadecimal addresses; they are not dereferenced.
- Functions without DWARF information simply have no argument suffix.

All events go to stdout by default; diagnostics and the final summary go to
stderr.

The wall-clock offset is sampled at startup from `CLOCK_REALTIME -
CLOCK_MONOTONIC`. If the system clock is stepped by NTP or the machine
suspends while tracing, wall-clock values drift; seconds since boot remain
exact.

### Depth semantics and filtering

Filtering happens at instrumentation time. A function excluded by
`--include`/`--exclude` produces no events and does not contribute a frame, so
`depth` counts only instrumented frames:

```
0 -> main
1 -> A          # B in between is not instrumented
1 <- A
0 <- main
```

`--max-depth N` hides events deeper than `N` but keeps tracking them, so the
depths of the remaining events stay correct.

`--indent N` is display-only: `depth * N` spaces are inserted before the
demangled name, leaving the arrow column fixed. It does not affect filtering or
the reconstructed depth.

CRT/startup functions (`_start`, `_init`, `frame_dummy`, ...) are ordinary
functions and are traced by default. As a result `main` normally appears at
depth 1 (called from `__libc_start_main` through `_start`). Exclude them if
you want `main` at depth 0:

```bash
--exclude '^_start$|^_init$|^_fini$'
```

In attach mode, tracing starts at the first function call after attachment.
Frames that were already on the stack when the probes were attached are not
known, so depth is relative to the attach point (the first observed frame is
depth 0).

### Latency histogram

`--histogram` appends a report to the same stream as the events (stdout or the
`-o` file) after the last event line. Each thread has two sections: the call
tree first, then the per-function histograms:

```
=== thread 26570 ===
Tree:
main
└── C(int)
    ├── B(int)
    │   └── A(int)
    └── A(int)

Histograms:
0. main
   calls=1  total=25.30us  avg=25.30us  min=25.30us  max=25.30us
   [ 16.38us,  32.77us)  1  ----------------------------------------
1. C(int)
   calls=1  total=9.30us  avg=9.30us  min=9.30us  max=9.30us
   [  8.19us,  16.38us)  1  ----------------------------------------
2. B(int)
   calls=1  total=4.10us  avg=4.10us  min=4.10us  max=4.10us
   [  4.10us,   8.19us)  1  ----------------------------------------
3. A(int)
   calls=1  total=1.77us  avg=1.77us  min=1.77us  max=1.77us
   [  1.02us,   2.05us)  1  ----------------------------------------
2. A(int)
   calls=1  total=1.44us  avg=1.44us  min=1.44us  max=1.44us
   [  1.02us,   2.05us)  1  ----------------------------------------
```

- One block per thread, sorted by TID.
- The `Tree:` section shows only the call structure, using `tree`-style
  connectors (`├──`, `└──`, `│`). Independent root trees within one thread are
  separated by a blank line.
- The `Histograms:` section lists entries as `<depth>. <function>`, where depth
  is relative to the thread's root. Entries follow the same DFS/preorder
  top-to-bottom order as the `Tree:` section; the depth number is not a sort
  key. Calls to the same function at the same depth are aggregated across
  callers; the same function at a different depth is listed separately.
- Histogram lines are indented under their `depth. function` heading, with no
  tree connectors. Each entry shows `calls`, `total`, `avg`, `min`, `max`, and
  the non-empty latency buckets.
- Latency is the inclusive time between the function's entry and its matching
  return, including instrumented callees.
- Histograms use power-of-two buckets: bucket 0 is exactly 0 ns; bucket `k` is
  `[2^(k-1), 2^k)` ns. Non-empty buckets are printed, including zero-count
  buckets between them.
- Calls without a matching return (exception unwinding, `longjmp`, lost events,
  or still running when tracing stops) are excluded from the histograms and
  reported as `incomplete: N call(s)`. A still-live frame is shown in the tree
  as `name  [incomplete]` and in the histogram section as
  `calls=0  [incomplete]`.
- `--max-depth` and `--indent` do not affect the histogram; `--max-depth` only
  hides event lines. `--include`/`--exclude` still apply at instrumentation
  time, so excluded functions do not appear.
- A recursive call is expanded once in the tree and marked `[recursive]`; its
  histogram entry is also marked `[recursive]` instead of being expanded
  forever.

## OTEL / Jaeger export

Each completed function invocation can be exported as an OpenTelemetry span:

- one trace per depth-0 root invocation by default
  (`--trace-scope=root`), so each thread and each top-level call has a
  meaningful trace boundary;
- one span per instrumented call, nested by the reconstructed call stack;
- `code.function`, `code.filepath`, `code.lineno`, `callgraph.function_id`,
  `callgraph.module`, `thread.id`, `thread.name`, and depth as span
  attributes;
- `callgraph.incomplete=true` and `callgraph.end_reason` for frames that never
  returned (desync or shutdown).

The network transports are:

- `--exporter otlp` uses OTLP/gRPC (default `localhost:4317`);
- `--exporter otlp-http` uses OTLP/HTTP with protobuf (default
  `http://localhost:4318`).

There is also a file backend:

- `--exporter otlp-json --export-file FILE` writes an OTLP/JSON request body
  without any network dependency.

OTLP/gRPC and OTLP/HTTP use the protobuf messages in
`third_party/opentelemetry-proto`.

```bash
# Start a Jaeger version with an OTLP receiver (v2, or all-in-one 1.35+).
docker run --rm -p 16686:16686 -p 4317:4317 -p 4318:4318 \
    jaegertracing/jaeger:latest

sudo ./build/callgraph run -T \
    --exporter otlp \
    --endpoint localhost:4317 \
    --service-name my_app \
    --exclude '^_start$|^_init$|^_fini$' \
    -- ./my_app
```

The same exporter options work in attach mode:

```bash
sudo ./build/callgraph attach -p 12345 \
    --exporter otlp \
    --endpoint localhost:4317 \
    --service-name my_app
```

Then open `http://localhost:16686` and select `my_app`. The trace page shows the
nested call tree. Jaeger displays individual traces, not an aggregated call
graph; use `--histogram` for the aggregate view. The same endpoint flag works
with an OpenTelemetry Collector, which can add batching, filtering, sampling,
and routing before exporting to Jaeger.

Batching uses `--batch-size` (spans) and `--flush-interval` (milliseconds).
The exporter queue is bounded and never blocks the ring-buffer collector.
`--compression gzip` applies to OTLP/HTTP; OTLP/gRPC compression is not
implemented.

Root-trace sampling is available with `--sample-rate R` (`0..1`, default
`1.0`). The decision is made once for the root and inherited by all
descendants, so Jaeger never receives a retained root with sampled-out
children. For more advanced policies, send complete traces through an
OpenTelemetry Collector and tail-sample there.

Source file and line attributes require DWARF; functions without debug info
simply omit them. Thread names are read from
`/proc/<pid>/task/<tid>/comm` when available; in restricted PID-namespace
setups the attribute may be absent.

To convert an existing text trace:

```bash
# -T records Unix-capable wall-clock timestamps.
sudo ./build/callgraph run -T -o trace.log -- ./my_app

./build/callgraph export --otel \
    --input trace.log --output spans.json --service-name my_app

curl -sS -X POST -H 'Content-Type: application/json' \
    --data-binary @spans.json http://localhost:4318/v1/traces
```

A default (boot-second) trace needs a timestamp anchor. Prefer recording a
sidecar during capture and passing it to the converter:

```bash
sudo ./build/callgraph run -o trace.log \
    --trace-metadata trace.meta -- ./my_app

./build/callgraph export --otel \
    --input trace.log --metadata trace.meta --output spans.json
```

If no sidecar exists and the trace was captured on this host in the current
boot session, `--assume-local-capture` derives an approximate anchor from the
local realtime/monotonic clocks and prints a warning:

```bash
./build/callgraph export --otel \
    --input trace.log --output spans.json --assume-local-capture
```

This is less accurate than `-T` or `--trace-metadata`, especially for old,
remote, or suspend-affected traces.

Text conversion limitations: it has no stable function IDs (same-demangled-name
static functions in different modules can merge), and `--show-args` suffixes
are stripped and preserved as `callgraph.arguments` only when
`--input-show-args` is given. Native export avoids both limitations.

See `docs/otel-export-design.md` for the full OTel mapping and edge-case semantics.

## Flamegraph export

`callgraph export --flame` converts a text trace into folded stacks:

```text
main 1
main;C(int) 1
main;C(int);B(int) 1
```

Each line is a root-to-function stack followed by its invocation count.
Identical stacks are aggregated, and the output is sorted for deterministic
diffs. Frames closed by desync or shutdown end in `[incomplete]`.

```bash
callgraph export --flame --input trace.log --output stacks.folded
flamegraph.pl stacks.folded > flame.svg
# or:
inferno-flamegraph stacks.folded > flame.svg
```

`--flame` writes to stdout when `--output` is omitted. It does not require a
timestamp anchor, OTLP metadata, or network access.

## Return probes: `uretprobe` vs `ret`

This is important for C++ programs.

### `--return-mode=uretprobe` (default)

One `uretprobe` per function. The kernel hijacks the function's return address
and redirects it through a trampoline. This is fast and gives exact return
events, but **the trampoline has no unwind metadata: if a C++ exception (or any
non-local unwind) passes through a traced function, the process will call
`std::terminate`**. `longjmp` and some sanitizers/unwinders can be affected as
well.

The tool prints a warning when the target contains `.gcc_except_table`
(evidence of C++ exception handling) and uretprobe mode is selected.

### `--return-mode=ret`

The resolver disassembles each function with libopcodes, finds its `ret`
instructions, and attaches ordinary uprobes there. The return address on the
stack is never modified, so exceptions and unwinding keep working.

Trade-offs:

- more probes (one per return instruction, not one per function)
- returns are reported at the `ret` instruction, just before the actual return
- frames unwound by an exception execute no `ret`, so they produce no return
  event; the next real return on that thread triggers the resynchronization
  logic and is counted as `desync`
- x86-64 (and 32-bit x86) only; requires `binutils-dev` at build time

Use `ret` for C++ programs that use exceptions, and `uretprobe` for C or
exception-free programs where the lower probe count matters.

### Non-local control flow (`longjmp`, exceptions, tail calls)

An entry/return pair cannot be observed when control leaves a function without
executing its return, as with `longjmp`/`siglongjmp`, exception unwinding, or a
tail call. Every entry event records the user stack pointer (`rsp`). Because a
callee always enters below its caller, the reconstructor drops any recorded
frame at or above the new call's `rsp` before pushing it. Those frames are
reported as `desync`, just like frames skipped by a matching return.

This is what keeps the reported depth bounded when a program repeatedly
`longjmp`s out of deep call trees, for example PostgreSQL's `PG_TRY`/`ereport`
error path: without it, frames below the jump target accumulate forever because
the jump target (such as `PostgresMain`) never returns. The same mechanism
repairs a lost return event at the next sibling call. Offline text traces do
not contain stack pointers, so `export --otel`/`--flame` replay keeps the
return-matching behaviour.

Go goroutines are stackful and need special care. Their stacks are
heap-allocated, grow by copying, and are switched by the Go scheduler. The
default `uretprobe` mode can crash the Go runtime during stack growth or GC,
because the runtime validates return PCs and sees the uretprobe trampoline; use
`--return-mode=ret` for Go binaries. Even then, the per-thread shadow stack
cannot follow goroutine switches or stack relocation, so nesting across
`Gosched`/channel operations and deep recursion is unreliable (expect extra
`desync`/`stray` events). C++20 coroutines are unaffected by the stack issue:
their frame is heap-allocated but the body runs on the resumer's stack.

## Architecture

```
CLI / process controller
        |
   ELF resolver (libelf, libdwfl, libopcodes)
        |
   Module manager (/proc/<pid>/maps)
        |
   Probe manager (libbpf uprobe_multi)
        |
   BPF programs + ring buffer
        |
   Event collector
        |
   Per-TID call-stack reconstruction
        |
        +--> Latency statistics + tree/histogram report (--histogram)
        |
        +--> Writer thread -> stdout / file
        |
        +--> Span generator -> OTLP/gRPC, OTLP/HTTP protobuf, or JSON file
```

The BPF programs are deliberately tiny: they emit `{timestamp, function_id,
tgid, tid, type, entry_rsp}` and do no symbol resolution. Function IDs are
per-offset cookies; user space owns the ID-to-name table and all stack logic.
The entry stack pointer lets the reconstructor detect frames unwound by
`longjmp`, exceptions, tail calls, or lost return events. With `--histogram`,
the call-stack reconstructor also accumulates per-thread caller-to-callee
latency histograms; the tree and histogram sections are rendered after the
collector stops and appended to the same stream by the writer.

Symbol resolution uses the ELF symbol table first (entry points are
`STT_FUNC` symbols in executable sections). C++ linkage names are demangled
with `abi::__cxa_demangle`. If `.symtab` is absent, libdwfl locates external
debug information through the build ID or `.gnu_debuglink` and its symbol table
is used instead; `dwfl_report_offline` reports PIE modules at a synthetic base,
so the module bias is subtracted before computing uprobe offsets. File offsets
come from the executable `PT_LOAD` segment:

```
file_offset = p_offset + (st_value - p_vaddr)
```

Aliases and identical-code-folded functions share a file offset; only one
probe is emitted per offset, with a preferred name.

## Exit summary

At exit the tool prints one line to stderr:

```
callgraph: N events, N entries, N returns, N lost, N desync, N stray, N dropped
```

- `lost`: ring-buffer reservation failures (the trace is incomplete)
- `desync`: frames skipped by a return, or dropped at an entry whose stack
  pointer shows they were unwound (exception, `longjmp`, tail call, lost event)
- `stray`: returns with no matching frame (e.g. attach started mid-stack)
- `dropped`: output lines dropped because the writer queue was full

When OTEL export is enabled, one additional line reports exported, dropped, and
failed span writes:

```
callgraph: OTLP 5 span(s) exported, 0 dropped, 0 failed
```

## Troubleshooting

**`failed to load BPF object: Operation not permitted`** — run as root or grant
`CAP_BPF`, `CAP_PERFMON`, and `CAP_SYS_ADMIN`. Check
`/proc/sys/kernel/perf_event_paranoid`.

**`uprobe_multi is unavailable`** — the kernel or libbpf is too old; the tool
falls back to individual uprobes. This works but attaches much more slowly.

**`failed to attach multi-uprobe: ... (-524)`** — `524` is the kernel-internal
`ENOTSUPP`, not the userspace `EOPNOTSUPP`/`ENOTSUP` (`95`). glibc and libbpf
have no name for it, which is why it is printed as `unknown error (-524)`; this
tool translates it to `Operation not supported (ENOTSUPP, kernel errno 524)`.
The kernel returns it while registering one offset in the batch: the byte there
is already an `int3` (`0xcc`), the offset is not an instruction boundary, or the
instruction cannot be single-stepped by uprobes (for example a segment/lock
prefix, or `cli`/`sti`/`popf`). A symbol that points into data or padding, or a
desynchronised `--return-mode=ret` scan, produces such offsets. The tool splits
the batch until the bad offset is isolated, skips that probe, and keeps the
rest. Run with `-v` to see the rejected offset; narrow `--module` if the offset
comes from an unexpected symbol.

**`no functions matched` / `has no .symtab`** — the binary is stripped and no
separate debug information was found. Install the matching debug file under
`/usr/lib/debug` or keep one next to the binary with a `.gnu_debuglink`, or
rebuild without stripping. With `--all-modules`, stripped libraries are
skipped; the rest still work.

**The application terminates with an exception under `uretprobe`** — see
[Return probes](#return-probes-uretprobe-vs-ret). Re-run with
`--return-mode=ret`.

**Shared-library calls at startup are missing** — module discovery polls
`/proc/<pid>/maps`, and a library's constructors may run before the first poll.
Attach mode has the same limitation for calls before attachment.

**Events missing / `lost` non-zero** — increase `--ringbuf-size` (power of two)
and write events to a file with `-o` so stdout backpressure does not stall the
collector.

**The application's own stdout is mixed with the trace in `run` mode** — both
use stdout. Write the trace to a file with `-o trace.log`, or run the program
in attach mode.

**`--exporter otlp` says protobuf is unavailable** — the binary was built
without protobuf/protoc. Install the protobuf development package and rebuild,
or use `--exporter otlp-json` with OTLP/JSON.

**`--exporter otlp-http` says libcurl is unavailable** — the binary was built
without libcurl. Use `--exporter otlp-json --export-file` and POST the file
yourself, or install the libcurl development package and rebuild.

**Jaeger shows no trace** — check that the OTLP receiver is on the expected port
(`4317` for gRPC, `4318` for OTLP/HTTP), that the service name matches, and that
the exporter reported `0 failed`. A long-lived root span is exported only when
it returns; completed child spans may already be present.

**`Cannot attach to pid` / ptrace denied** — attach mode needs ptrace access
(same user, Yama `ptrace_scope`, or root).

## Layout

```
CMakeLists.txt
bpf/trace.bpf.c, bpf/trace.h    BPF programs and shared event layout
include/callgraph/              headers
src/                            resolver, modules, probes, collector, stack, output,
                                clock converter, span generator, OTLP encoders,
                                exporter, offline parser
examples/                       simple, recursive, multithread, exceptions, loop, lib
tests/                          unit and integration tests
tools/install-deps.sh           distro-aware build dependency installer
tools/legacy/                   earlier bpftrace generator (Python)
third_party/libbpf/             vendored libbpf v1.5.0
third_party/opentelemetry-proto/ vendored OTLP protobuf definitions
docs/design-notes.md            design decisions and phase plan
docs/otel-export-design.md      OTEL/Jaeger export design
```

## Legacy prototype

`tools/legacy/gen_callgraph.py` is the earlier Python generator that emitted a
bpftrace script from `nm -C` output. It is kept for quick ad-hoc use; the C++
tool supersedes it.
