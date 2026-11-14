# AGENTS.md

## Repository

- Linux-only C++20 eBPF/uprobe function tracer. Single binary: `build/callgraph`.
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
- Required system deps: libelf, libdw, zlib, pthreads. Optional: libcurl (network OTLP), protobuf/protoc (OTLP/gRPC and HTTP/protobuf), libopcodes (enables `--return-mode=ret`).
- CMake prints which optional features are enabled. `callgraph --version` also reports `otlp protobuf: yes/no` and `otlp http: yes/no`.
- Generated OTLP `.pb.cc/.pb.h` files live under `build/`; never edit or commit them.
- `build/`, `compile_commands.json`, and all non-`.cpp` files under `examples/` are ignored.

## Test

```bash
./build/callgraph_tests                         # all unit tests
ctest --test-dir build -R unit --output-on-failure
bash tests/integration.sh ./build/callgraph     # non-root: tracing tests are skipped
sudo bash tests/integration.sh ./build/callgraph # full tracing + attach coverage
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
- `--max-depth` and `--indent` are display-only and do not affect exported spans.
- `--no-rsp-resync` disables the entry-`rsp` unwind heuristic for stackful runtimes (`ucontext`, Boost.Context, Go); pair it with `--return-mode=ret`.
- The same `--exporter` options work in both `run` and `attach` mode.
- `callgraph export --otel` converts text traces to OTLP/JSON and does not need root; `callgraph export --flame` emits folded stacks. See the mode-specific `--help`.

## Runtime requirements and gotchas

- Tracing needs root or `CAP_BPF`+`CAP_PERFMON`+`CAP_SYS_ADMIN`; attach also needs ptrace permission.
- `uprobe_multi` needs Linux 6.6+; older kernels fall back to individual uprobes.
- The target must retain `.symtab`, or have separate debug info discoverable by build ID / `.gnu_debuglink`. A stripped binary without debug info is not traceable.
- `--show-args` is x86-64 only and needs DWARF.
- `--return-mode=uretprobe` can terminate C++ programs that unwind exceptions through traced functions. Use `--return-mode=ret` for those; it is only available when libopcodes is found.
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
- `docs/kernel-event-design.md` describes a separate kernel-event stream correlated with the user call stack. P0 MVP is implemented for sched, futex, I/O syscalls, and block events (`--sched`, `--futex`, `--io`, `--block`, `--kernel-events`, `--kernel-report`). Network, memory, PMU, and offline kernel-line replay are not implemented.
- The kernel BPF object (`bpf/kernel/`) is separate from the function uprobe object and uses runtime tracefs field offsets. `KernelTimeline` owns interval accounting; BPF stays stateless. `KernelProbeManager` learns target TIDs from `/proc` and from uprobe events because of PID-namespace differences.
- `SpanGenerator` turns call events into OTel spans; `OtelExporter` owns batching/queue/retry/transport; `ClockConverter` maps monotonic timestamps to Unix epoch.
- `TraceParser` + `callgraph export --otel|--flame` replay text traces through the same `CallStack` path; the text depth column closes frames at or above each entry's depth.
- Source file/line attributes are populated from libdwfl in the ELF resolver.

## OpenCode session tooling

These are user-level OpenCode helpers, not build requirements.

- Use `cpp-builder` for focused compile/link fixes, `cpp-test` for a specific test, `cpp-debugger` for crashes/sanitizer reports/hangs, and `cpp-reviewer` for diff reviews.
- Use `explore` for codebase search; use `general` only for independent multi-step work.
- Relevant skills/commands: `cpp-build`, `cpp-test`, `cpp-debug` skills and `/cpp-build`, `/cpp-test`, `/cpp-debug`, `/cpp-review` commands.
- There is no `.codegraph/` index in this repo; skip CodeGraph searches.

## Editing conventions

- C++20, four-space indentation, `callgraph` namespace, RAII for fds/pointers. `fail()` throws `Error`; `main` catches and reports it.
- Keep the tracing core independent of the OTel export layer; text output must keep working.
- Update `README.md`, `docs/otel-export-design.md`, and relevant tests when changing CLI, span mapping, or export behavior.
- Prefer existing helpers (`common.h`, `Output`, `CallStack`) over duplicating stack/timestamp logic.
