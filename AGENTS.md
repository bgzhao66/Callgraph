# AGENTS.md

## Repository

- Linux-only C++20 eBPF/uprobe function tracer. Three executables share `callgraph_core`/`callgraph_trace`: `build/callgraph-run`, `build/callgraph-attach`, and `build/callgraph-export`, plus the standalone `build/callgraph-disasm` and the `callgraph` wrapper.
- `bpf/` contains the tiny eBPF event program; `src/` and `include/callgraph/` are the userspace tracer.
- `tests/unit/test_main.cpp` is the whole unit-test suite. `tests/integration.sh` is the integration suite.
- `third_party/libbpf` is a git submodule. `third_party/opentelemetry-proto` is vendored source.
- `tools/legacy/` is an old Python bpftrace generator; it is not built or tested.

## Build

```bash
git submodule update --init --recursive
cmake -S . -B build -DCMAKE_BUILD_TYPE=RelWithDebInfo
cmake --build build -j
```

- `clang` with the BPF target is required at configure/build time; `bpf/trace.bpf.c` is compiled and embedded into the binary.
- `tools/install-deps.sh` installs distro packages and initializes the libbpf submodule; use `--minimal` to skip optional feature packages.
- Required system deps: libelf, libdw, zlib, pthreads, and libopcodes (for `callgraph-disasm` only). Optional: libcurl (network OTLP), protobuf/protoc (OTLP/gRPC and HTTP/protobuf).
- Five release artifacts: `callgraph-run`, `callgraph-attach`, `callgraph-export` (none links libopcodes/libbfd), `callgraph-disasm` (GPL-3.0-only facts generator), and `callgraph` (a bash wrapper, not a compiled dispatcher). There is no community build.
- CMake prints which optional features are enabled. Each `callgraph-run|attach|export --version` reports `otlp protobuf: yes/no` and `otlp http: yes/no`; the run/attach binaries also print the libbpf version.
- Generated OTLP `.pb.cc/.pb.h` files live under `build/`; never edit or commit them.
- `build/`, `compile_commands.json`, and all non-`.cpp` files under `examples/` are ignored.

## Test

```bash
./build/callgraph_tests                         # all unit tests
ctest --test-dir build -R unit --output-on-failure
bash tests/integration.sh ./build               # non-root: tracing tests are skipped
sudo bash tests/integration.sh ./build          # full tracing + attach coverage
```

- The unit tests are a custom `CHECK`-macro runner, not gtest. There is no per-test filter; add a test function and call it from `main()` in `tests/unit/test_main.cpp`.
- A non-root integration run exits successfully but does **not** exercise probes. A green non-root run is not proof that tracing works.
- The integration script compiles `examples/*.cpp` with `g++ -O0 -g`; source-line assertions require DWARF.
- Python 3 is used for OTLP JSON/HTTP checks when available; those checks are skipped otherwise.
- Full integration requires root (or the capabilities below), ptrace for attach, and is slower because it starts live run/attach targets.
- There are no CI workflows, formatter, or linter configs. Run the build and both test suites manually.

## CLI contract

- Do not reintroduce the old `--otel-*` flags. The CLI was deliberately collapsed to one namespace.
- Exporter selector: `--exporter stdout|otlp|otlp-http|otlp-json` (default `stdout`).
- Network exporters use `--endpoint`; `otlp-json` uses `--export-file`.
- `--batch-size` is the OTLP batch size. `--probe-batch-size` is the `uprobe_multi` attachment batch. Do not conflate them.
- `--complete-traces` is opt-in and valid for network exporters (`otlp`, `otlp-http`), `otlp-json`, and offline `--otel` export to `--output` or `--endpoint`. It buffers a trace until all spans close and a root exists, then exports it root-first. `--trace-buffer-bytes` (default 256m) and `--trace-buffer-spans` (default 1000000) bound the buffer; an overflow drops the whole trace as `trace-buffer-overflow`.
- `--ingest-sample-rate R` (0..1, default 1) gates text and spans at the root entry; rejected traces are still stack-tracked and kernel events are unaffected. `--log-rate-limit N` (default 0 = off) limits stdout text lines with separate user and kernel token buckets, each at `N` lines per second over event timestamps. Suppressed lines are reported to stderr every 5 seconds as a delta since the previous report, split by user and kernel; the final summary shows the cumulative total. It does not affect `--histogram`, file output, or spans.
- `--sample-rate` is the baseline export sampling rate. `--outlier-latency-quantile Q` (0 < Q < 1) requires `--complete-traces` and exports traces above the `Q` trace-duration quantile regardless of the baseline sample; warm-up is 100 traces. While it is active, every exported root span carries the double attribute `callgraph.quantile`. Intentional outlier filtering is not an `OtelDropReason`.
- With `--kernel` and an OTel exporter, TID-specific kernel events are exported as child spans automatically. Syscall enter/exit, direct reclaim, and scheduler off-CPU/runqueue are intervals; page faults, wakeups, migrations, fork, and exit are zero-duration point spans. Kernel spans attach to the innermost open kernel span or user-function span and use `thread.id`, `callgraph.depth` (parent depth + 1), and `callgraph.kernel.user_depth`, with `callgraph.kernel.*` attributes and no `code.*` source attributes. Syscall span names are `@<syscall>` (`@read`, `@sendto`), while `callgraph.kernel.event` stays unprefixed. Block requests and TCP retransmits are global and remain text-only. No separate kernel-span flag exists.

- `--histogram --kernel` nests a `kernel:` block under each user-frame histogram entry, keyed by the full root-first `CallPath`. Interval labels are `@<syscall>`, `sched.off_cpu`, `sched.runqueue`, and `direct_reclaim`; point events are `page_fault.user`/`page_fault.kernel`, `sched.wakeup`/`sched.waking`/`sched.wakeup_new`, `sched.migrate`, `proc.fork`, and `proc.exit`. Kernel bars scale against the owning frame's inclusive total, and cut-short intervals are marked `[incomplete]`. Global block and TCP retransmits stay text-only.
- The `run`/`attach`/`export` subcommand tokens no longer exist. `callgraph-run` takes `-- PROGRAM`, `callgraph-attach` takes `-p PID`, and `callgraph-export` takes `--otel|--flame|--static`. `-p/--pid` is rejected by `callgraph-run`; `--` is rejected by `callgraph-attach`.
- `--max-depth` and `--indent` are display-only and do not affect exported spans. `--trace-depth N` is structural: it keeps only N levels below each thread's root, and deeper user frames are not reconstructed, so they produce no text, spans, or histograms. The default is unlimited; `0` keeps only the root, and `-1` is an internal sentinel that is rejected as an explicit argument. Kernel events are not capped. `CallStack`'s internal default is also unlimited so offline replay is unchanged.
- `--root-scope GLOB` selects functions that may start a traced tree. The outermost match per thread is depth 0; descendants are traced up to `--trace-depth` even when they do not match. `--exclude` removes a node and splices its descendants. With `--trace-depth N > 0`, static call-graph pruning follows direct calls only: resolved `call` and unconditional `jmp` edges are traversed, and indirect call sites add no targets. Omitting `--trace-depth` runs no pruning, so every non-excluded function (including possible indirect callees) is instrumented; this is the conservative mode. No separate `--static-prune` flag exists. If analysis is unavailable (no facts for the module and no built-in disassembler), no user functions are instrumented implicitly: explicit `--root-scope` matches only, or none when absent, with a warning. Attach mode without `--root-scope` cannot seed roots and instruments nothing implicitly for `N >= 0`.
- Kernel presets are `latency` (default), `proxy`, `storage`, `computation`, `full`, and `extended`. They select fine-grained scopes: `latency` covers sched/futex/io/network-syscalls and excludes block, direct reclaim, page-fault points, and TCP retransmits; `proxy` adds global TCP retransmits and direct reclaim and drops block; `storage` keeps io/direct-reclaim and drops network/page-faults; `computation` keeps sched/futex/reclaim/page-faults; `full` enables everything except block; `extended` adds block to `full`. `--memory` still means reclaim + faults, `--network` still means network syscalls + TCP retransmits, and presets are additive. Presets never change `--trace-scope`. Block is global: `extended` includes it, other presets add it via `--block`, and `--kernel --block` alone selects block-only tracing like `--kernel --sched` selects scheduler-only tracing. Explicit family flags are additive and suppress the implicit latency default (`--block --io --network` selects exactly those three families).
- `--no-rsp-resync` disables the entry-`rsp` unwind heuristic for stackful runtimes (`ucontext`, Boost.Context, Go); pair it with `--return-mode=ret`.
- The same `--exporter` options work in both `run` and `attach` mode.
- `callgraph-export --otel` converts text traces to OTLP/JSON and does not need root; `callgraph-export --flame` emits folded stacks; `callgraph-export --static --static-graph FILE` renders a direct-call tree from facts written by `callgraph-disasm`. The tracer has no positional MODULE form and no `--all-modules` in static export mode; both now belong to the generator.
- `--static-graph FILE` (repeatable) is the only way the tracer obtains a call graph or `ret` offsets. It is consumed by `--trace-depth N >= 0`, `--return-mode=ret`, and `export --static`. Modules are joined by build-id, then canonical path, then function `low_pc`.
- `--static` is mutually exclusive with `--otel`/`--flame`; `--root-scope`/`--regex` post-filter roots from the facts; `--exclude` is not supported there. The renderer follows direct `call`/unconditional `jmp` edges inside one module, expands each function's subtree once per module (later occurrences end with `[...]`), keeps self-edges so recursion renders as `[recursive]`, and separates root sections with a blank line. Default roots are `main` (first), the ELF entry, init/fini arrays, exported symbols, and address-taken functions; a multi-module document prints `== PATH ==` before each section and skips later modules with no root match.
- Facts carry `"prunable": false` for modules with IFUNC targets or `setcontext`/`swapcontext`; `ret` offsets remain usable, but pruning and static export reject them (`--trace-depth` warns and degrades, the first static-export module is a hard error).
- `callgraph-disasm [options] MODULE` supports only `-o/--output`, `--all-modules`, `-h/--help`, and `--version`. It always emits functions, flags, edges, default roots, and return offsets as compact JSON (format `callgraph-static-graph`, version 1). Unanalysable dependency modules warn and are omitted; the primary module is fatal. Do not grow it into a second tracer or add a TSV format.
- `--show-args` is the single flag for live argument capture and offline text-suffix replay. Do not reintroduce `--input-show-args`.
- Help follows the `git <cmd>` convention: a lowercase `usage:` line, the composite command name (`callgraph run`, `callgraph attach`, `callgraph export`, `callgraph disasm`), and lowercase angle-bracket metavariables (`<file>`, `<glob>`, `<n>`). The executables remain `callgraph-run`/`callgraph-attach`/`callgraph-export`/`callgraph-disasm`, and `--version`/diagnostic prefixes keep those names.
- `callgraph run` and `callgraph attach` pages show usage, Tracing options, Kernel event options, Live export options, General options, and mode-specific examples. `callgraph export` shows usage, Offline export options, General options, and export examples; `callgraph export --otel|--flame|--static --help` narrows to that mode, while bare `callgraph export --help` lists all three. `callgraph disasm --help` covers the facts generator. Errors print only the invoking program's `usage:` block plus a `--help` hint. `-h` and `--help` are equivalent. `callgraph` forwards help/version without generating facts.
- Help output uses up to three levels: master options (`--kernel`, `--exporter`, `--otel`, `--flame`, `--static`) stay at the normal indent, the options that refine or require them are indented four spaces further, and values such as `--preset` scopes are indented four spaces under their option. Descriptions share one column so the names read as a table. Keep new sub-options under their master.

## Runtime requirements and gotchas

- Tracing needs root or `CAP_BPF`+`CAP_PERFMON`+`CAP_SYS_ADMIN`; attach also needs ptrace permission.
- `uprobe_multi` needs Linux 6.6+; older kernels fall back to individual uprobes.
- The target must retain `.symtab`, or have separate debug info discoverable by build ID / `.gnu_debuglink`. A stripped binary without debug info is not traceable.
- `--show-args` needs DWARF and is x86-64 only for live capture; offline `export --otel --show-args` only replays text suffixes and is architecture-independent.
- `--return-mode=uretprobe` can terminate C++ programs that unwind exceptions through traced functions. Use `--return-mode=ret` for those; it requires `--static-graph` facts and never silently falls back to `uretprobe`. Missing facts for the primary module are a hard error before probes attach (and before the child starts in `run` mode); missing facts for a later-discovered module warn and skip that module.
- Go binaries are detected via `.note.go.buildid`/`.go.buildinfo` and trigger a warning: `uretprobe` can crash the Go runtime during stack growth/GC, and goroutine stack switches make nesting unreliable even in `ret` mode. Go binaries built with `-ldflags="-s -w"` have no symbol table and are rejected.
- Stackful coroutines (`ucontext`, Boost.Context) need `--return-mode=ret` for returns across a switch and `--no-rsp-resync` to avoid dropping suspended frames; nesting across the switch is still not joined.
- Attach mode starts at the attach point. The first observed frame is a root marked `callgraph.partial_stack=true`; calls before attachment are not seen.
- Default OTel trace scope is one trace per depth-0 root invocation (`--trace-scope=root`). Thread and process scopes are available for special cases.
- OTLP/gRPC and OTLP/HTTP protobuf require protobuf/protoc; network export requires libcurl. JSON file export works without either.
- `--exporter otlp-json` writes OTLP/JSON to `--export-file`, not to the text `-o/--output` stream.

## Architecture map

- BPF emits a fixed 136-byte event (`ts`, function cookie, tgid/tid, type, entry `rsp`, captured args). It does no symbol resolution.
- Userspace owns ELF/DWARF resolution, module discovery, probe attachment, and per-TID call-stack reconstruction.
- `CallStack` pairs entry/return events, handles recursion/desync/shutdown, and feeds `SpanSink`. Entry `rsp` lets it drop frames unwound by `longjmp`, exceptions, tail calls, or lost returns; offline text traces carry `rsp=0` and skip that check.
- `--histogram` emits a `Tree:`/`Histograms:` pair per root (one root's call tree immediately followed by its histogram entries labeled `depth. function` in DFS order); siblings and roots are listed in call order, tree nodes end with their inclusive per-call-path total (a function reached from several callers appears once per path, and each node's total is consistent with its subtree) in a per-node best-fit unit laid out in per-unit columns (`s`, `ms`, `us`, `ns`; same unit, same column) joined to the label by a middle-dot (`·`) leader, and each histogram entry starts with a bar sized by its inclusive total relative to the root span's duration. Do not reintroduce interleaved bucket lines in the tree.
- `docs/kernel-event-design.md` describes a separate kernel-event stream correlated with the user call stack. Implemented families are sched, futex, I/O syscalls, block, memory (page faults and direct reclaim), and network (socket syscalls and global TCP retransmits) behind the `--kernel` master switch (`--events`, `--preset`, `--merge-window`, `--require-events`, and the `--sched`/`--futex`/`--io`/`--block`/`--network`/`--memory` shortcuts). There is no `--report` summary; `--histogram` is the aggregate view. PMU, IRQ/workqueue, and offline kernel-line replay are not implemented.
- The kernel BPF object (`bpf/kernel/`) is separate from the function uprobe object and uses runtime tracefs field offsets. `KernelTimeline` owns interval accounting; BPF stays stateless. `KernelProbeManager` learns target TIDs from `/proc` and from uprobe events because of PID-namespace differences.
- `SpanGenerator` turns call events into OTel spans; `OtelExporter` owns batching/queue/retry/transport; `ClockConverter` maps monotonic timestamps to Unix epoch.
- `TraceParser` + `callgraph-export --otel|--flame` replay text traces through the same `CallStack` path; the text depth column closes frames at or above each entry's depth.
- Static analysis is split by license boundary. `static_elf_facts.cpp` (libelf) provides `Node`/`Ranges`/`collect_elf_facts`; `static_prune.cpp` implements `build_nodes`, `prune_statically`, `select_roots`, and `static_graph_roots` over injected edges. `static_disasm.cpp` (libopcodes, `callgraph-disasm` only) provides `collect_code_facts`, the `ret` scan, and `build_static_graph_module`; the tracer installs no code-facts collector. `static_graph_json_write.cpp`/`static_graph_json_read.cpp` implement the compact JSON format and the by-`low_pc` join; `static_graph_export.cpp` renders the tree iteratively with Unicode connectors and path-cycle cuts. `module_dependencies.cpp` resolves the generator's `--all-modules` closure through `PT_INTERP` or the host loader's `--list`.
- `callgraph` is pure orchestration: it parses wrapper options, decides whether facts are needed, runs `callgraph-disasm`, then invokes the tracer with `--static-graph`. Without temporary facts it `exec`s the tracer (one process hop). With temporary facts it waits for the child, removes its `$TMPDIR/callgraph-facts.*` directory from an EXIT trap, and exits with the child's status; INT/TERM are trapped so cleanup also runs on signals. It locates the binaries next to its own resolved real path (symlinks and PATH invocation handled), with `CALLGRAPH_RUN`/`CALLGRAPH_ATTACH`/`CALLGRAPH_EXPORT`/`CALLGRAPH_DISASM` overrides. It must stay MIT-licensed and contain no analysis logic.
- `docs/static-graph-format.md` is the versioned facts schema; `LICENSING.md` maps artifacts and files to licenses.
- Source file/line attributes are populated from libdwfl in the ELF resolver.

## OpenCode session tooling

These are user-level OpenCode helpers, not build requirements.

- Use `cpp-builder` for focused compile/link fixes, `cpp-test` for a specific test, `cpp-debugger` for crashes/sanitizer reports/hangs, and `cpp-reviewer` for diff reviews.
- Use `explore` for codebase search; use `general` only for independent multi-step work.
- Relevant skills/commands: `cpp-build`, `cpp-test`, `cpp-debug` skills and `/cpp-build`, `/cpp-test`, `/cpp-debug`, `/cpp-review` commands.
- There is no `.codegraph/` index in this repo; skip CodeGraph searches.

## Editing conventions

- C++20, four-space indentation, `callgraph` namespace, RAII for fds/pointers. `fail()` throws `Error`; `trace_program`/`export_program` catch and report it with the invoked program name.
- Keep the tracing core independent of the OTel export layer; text output must keep working.
- Update `README.md`, `docs/otel-export-design.md`, and relevant tests when changing CLI, span mapping, or export behavior.
- Prefer existing helpers (`common.h`, `Output`, `CallStack`) over duplicating stack/timestamp logic.
