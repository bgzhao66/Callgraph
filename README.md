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
- two return-probe modes: `uretprobe` (default) and `ret` (exception-safe)

Not implemented yet: execution-time statistics and child-process (`fork`)
following.

## Requirements

| Component | Needed for |
|---|---|
| Linux 6.6+ | `uprobe_multi` (older kernels fall back to individual uprobes) |
| C++20 compiler, CMake 3.20+ | host build |
| clang with the BPF target | compiling `bpf/trace.bpf.c` |
| libelf, libdw, zlib | ELF symbols, external debug info, compression |
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

## Usage

```bash
# Launch and trace from the first instruction
sudo ./build/callgraph run -- ./my_app arg1 arg2

# Wall-clock timestamps instead of seconds since boot
sudo ./build/callgraph run -T -- ./my_app

# Indent names by depth (two spaces per level)
sudo ./build/callgraph run --indent 2 -- ./my_app

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
```

### Options

```
Usage:
  callgraph run [options] -- program [args...]
  callgraph attach [options] -p PID

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
      --batch-size N    functions per uprobe_multi link (default: 1000)
      --ringbuf-size N  ring buffer size, k/m/g suffix (default: 16m)
      --dry-run         list resolved functions and exit
  -v, --verbose         verbose diagnostics
  -h, --help            show help
      --version         show version
```

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
   Writer thread -> stdout / file
```

The BPF programs are deliberately tiny: they emit `{timestamp, function_id,
tgid, tid, type}` and do no symbol resolution. Function IDs are per-offset
cookies; user space owns the ID-to-name table and all stack logic.

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
- `desync`: frames skipped by a return (exception, `longjmp`, tail call, lost
  event)
- `stray`: returns with no matching frame (e.g. attach started mid-stack)
- `dropped`: output lines dropped because the writer queue was full

## Troubleshooting

**`failed to load BPF object: Operation not permitted`** — run as root or grant
`CAP_BPF`, `CAP_PERFMON`, and `CAP_SYS_ADMIN`. Check
`/proc/sys/kernel/perf_event_paranoid`.

**`uprobe_multi is unavailable`** — the kernel or libbpf is too old; the tool
falls back to individual uprobes. This works but attaches much more slowly.

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

**`Cannot attach to pid` / ptrace denied** — attach mode needs ptrace access
(same user, Yama `ptrace_scope`, or root).

## Layout

```
CMakeLists.txt
bpf/trace.bpf.c, bpf/trace.h    BPF programs and shared event layout
include/callgraph/              headers
src/                            resolver, modules, probes, collector, stack, output
examples/                       simple, recursive, multithread, exceptions, loop, lib
tests/                          unit and integration tests
tools/legacy/                   earlier bpftrace generator (Python)
third_party/libbpf/             vendored libbpf v1.5.0
docs/design-notes.md            design decisions and phase plan
```

## Legacy prototype

`tools/legacy/gen_callgraph.py` is the earlier Python generator that emitted a
bpftrace script from `nm -C` output. It is kept for quick ad-hoc use; the C++
tool supersedes it.
