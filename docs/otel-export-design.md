# OTEL / Jaeger export design

Status: implemented. The tracing engine remains independent of OpenTelemetry;
OTLP export is a pluggable output backend alongside the existing text stream.

## 1. Objective

Convert the existing function entry/return event stream into OpenTelemetry
spans so that function execution trees can be ingested, queried, and visualized
by Jaeger.

A function invocation becomes one span:

- function entry creates the span and records `start_time`;
- function return completes the span and records `end_time`;
- nested calls become child spans through `parent_span_id`;
- each Linux thread has its own active-span stack;
- the traced process is represented by the OTel resource/service.

The BPF/libbpf/uprobe/ELF/DWARF tracing core is unchanged. Span generation and
export live in user space.

## 2. Event mapping

Current event format:

```
<ts> <tid> : <depth> -> <func>
<ts> <tid> : <depth> <- <func>
```

Example:

```
1234567890 4242 : 0 -> main
1234567895 4242 : 1 -> C(int)
1234567897 4242 : 2 -> B(int)
1234567900 4242 : 2 <- B(int)
1234567902 4242 : 1 <- C(int)
1234567905 4242 : 0 <- main
```

This produces:

```
main        [1234567890, 1234567905]
└── C(int)  [1234567895, 1234567902]
    └── B(int) [1234567897, 1234567900]
```

| callgraph concept | OpenTelemetry concept |
|---|---|
| Function invocation | Span |
| Function name | `span.name`, `code.function` |
| Entry timestamp | `span.start_time` |
| Return timestamp | `span.end_time` |
| Parent function | `parent_span_id` |
| Function ID | `callgraph.function_id` |
| PID | `process.pid` resource attribute |
| TID | `thread.id` / `thread.name` |
| Source file and line | `code.filepath`, `code.lineno` |
| Execution duration | Span duration |
| Module | `callgraph.module` |

Because the text stream is an event log, the converter maintains invocation
state until the matching return arrives. The existing `CallStack` matching and
desync logic is reused rather than duplicated.

## 3. Trace identity and span identity

OTLP requires 16-byte trace IDs, 8-byte span IDs, and an optional parent span
ID. Identifiers are generated in user space:

```cpp
struct SpanContext {
    TraceId trace_id;       // 16 bytes
    uint64_t span_id;       // 8 bytes
    uint64_t parent_span_id; // 8 bytes, zero for roots
};
```

`SpanContextManager` generates trace IDs from a per-session random seed, TID,
and root sequence. Span IDs are monotonic per-session tokens, guaranteed unique
within a trace and across the session. All-zero IDs are never emitted.

### Trace boundary

The default is one trace per top-level function invocation:

```
Thread 4242:                    Thread 4243:
  main()                          WorkerThread()
    Database::Open()                Database::Update()
    Database::Insert()
```

Trace A contains `main` and descendants; Trace B contains `WorkerThread` and
descendants. A long-running worker generates a new trace for each top-level
invocation. This keeps Jaeger traces meaningful and bounded.

`--trace-scope=thread` is also available for grouping all roots of one TID
into one trace, and `process` for a single process-wide trace (debug use).

### Span generation

On entry:

1. Look up the thread's active span stack.
2. If empty, start a new trace and root span.
3. Otherwise inherit the parent's trace ID and set `parent_span_id`.
4. Generate a new span ID.
5. Record the start timestamp.
6. Push the span.

On return:

1. Find the active span for the returning function.
2. Record the end timestamp and duration.
3. Close the span.
4. Pop it.
5. Submit it to the export pipeline.

Recursion is preserved because every invocation gets a distinct span ID.

## 4. Timestamp conversion

`bpf_ktime_get_ns()` returns `CLOCK_MONOTONIC` nanoseconds. OTLP timestamps are
Unix epoch nanoseconds.

`ClockConverter` brackets a monotonic read between two realtime reads:

```
clock_gettime(CLOCK_REALTIME, &real_before);
clock_gettime(CLOCK_MONOTONIC, &mono);
clock_gettime(CLOCK_REALTIME, &real_after);

offset_ns = midpoint(real_before, real_after) - mono;
unix_ns   = monotonic_ns + offset_ns;
```

The offset is sampled at startup and recalibrated every 30 seconds during a
long-running trace. Span start and end are converted with the same offset at
close time, so durations remain exact even if the wall clock is stepped.

The original monotonic timestamps are retained internally for durations.
`bpf_ktime_get_ns()` is never exported directly as a Unix timestamp.

Offline text conversion uses the same rule:

- ISO 8601 timestamps are converted directly to epoch nanoseconds;
- boot-second timestamps require a `--trace-metadata` sidecar (preferred) or
  `--assume-local-capture`, and the converter rejects unanchored input.

## 5. Resource and span attributes

### Resource

| Attribute | Value |
|---|---|
| `service.name` | Application name (exe basename, or override) |
| `service.instance.id` | Per-session identifier |
| `process.pid` | Linux PID |
| `process.executable.path` | Executable path |
| `process.executable.name` | Executable name |
| `process.command_line` | Launch/attach command line |
| `host.name`, `host.arch`, `os.type`, `os.description` | Host details |
| `callgraph.return_mode` | `uretprobe` or `ret` |
| `callgraph.trace_scope` | `root`, `thread`, or `process` |
| `callgraph.attach_mode` | Whether tracing started by attach |
| `callgraph.version` | Tool version |

### Span

| Attribute | Value |
|---|---|
| `code.function` | Demangled function name |
| `code.function.name` | Newer semantic-convention alias |
| `code.filepath` | Source file from DWARF |
| `code.lineno` | Source line from DWARF |
| `callgraph.function_id` | Internal function ID |
| `callgraph.module` | ELF module basename |
| `callgraph.module.path` | Full ELF path |
| `callgraph.module.build_id` | ELF build ID |
| `callgraph.file_offset` | Probe file offset |
| `thread.id` | Linux TID |
| `thread.name` | Thread name from `/proc` when available |
| `callgraph.depth` | Instrumented call depth |
| `callgraph.root` | True for depth-0 spans |
| `callgraph.partial_stack` | Attach-mode root with unknown caller |
| `callgraph.arguments` | Formatted `--show-args` suffix |
| `callgraph.incomplete` | Closed by desync or shutdown |
| `callgraph.end_reason` | `desync` or `shutdown` |

Source attributes are omitted when DWARF is unavailable. Thread names are
best-effort; restricted PID-namespace setups may not expose
`/proc/<pid>/task/<tid>/comm`.

## 6. Export architecture

```
             eBPF Runtime
                  |
                  v
             Ring Buffer
                  |
                  v
            Event Collector
                  |
                  v
          Call-Stack Engine
                  |
                  v
           Span Generator
                  |
                  v
          Completed Span Queue
                  |
                  v
          OTel Batch Processor
                  |
                  v
             OTLP Exporter
                  |
                  v
           OTLP Collector
                  |
                  v
                Jaeger
```

Components:

| Component | Responsibility |
|---|---|
| `ClockConverter` | Monotonic-to-Unix conversion and recalibration |
| `SpanContextManager` | Trace/span ID generation |
| `SpanGenerator` | Entry/return events to `SpanRecord` |
| `SpanSink` | CallStack-to-generator callback boundary |
| `OtelExporter` | Bounded queue, batching, retries, transport |
| `OtelConfig` | Endpoint, protocol, batching, resource attributes |
| `TraceParser` | Offline text-trace conversion |

`SpanGenerator` is called on the collector thread and only builds records. The
exporter thread performs protobuf serialization and network I/O, so a slow
collector or unavailable endpoint cannot block the ring-buffer consumer.

## 7. Export protocol

| Mode | CLI | Default endpoint | Payload |
|---|---|---|---|
| gRPC | `--exporter otlp` | `localhost:4317` | OTLP protobuf over HTTP/2 |
| HTTP | `--exporter otlp-http` | `http://localhost:4318` | OTLP protobuf over HTTP |
| JSON file | `--exporter otlp-json --export-file FILE` | none | OTLP/JSON request body |

The gRPC path uses HTTP/2 prior knowledge for plaintext endpoints and HTTP/2
over TLS for `https://`. Requests are gRPC-framed and success requires a 2xx
HTTP status and, when present, `grpc-status: 0`.

OTLP protobuf definitions are vendored under
`third_party/opentelemetry-proto` and generated at build time with `protoc`.
This provides the same wire format as the official OpenTelemetry C++ SDK while
keeping the build self-contained. If `protobuf`/`protoc` is unavailable:
`--exporter otlp` and `--exporter otlp-http` are rejected, but
`--exporter otlp-json --export-file FILE` still works.

If libcurl is unavailable, network export is rejected but file export remains
available.

## 8. High-frequency calls and sampling

Function tracing can produce very high span rates. The exporter provides:

- batching (`--batch-size`, `--flush-interval`);
- a bounded span queue;
- retry with backoff;
- dropped/failed counters;
- instrumentation filters (`--include`, `--exclude`);
- root-trace sampling (`--sample-rate 0..1`).

Root-trace sampling is consistent: the decision is made once for the root and
inherited by every descendant. A retained root never has sampled-out children.
The default is no sampling (`1.0`). For tail sampling, forward complete traces
through an OpenTelemetry Collector.

## 9. Incomplete traces and errors

| Condition | Treatment |
|---|---|
| Normal return | Complete span normally |
| Missing return / desync | Close with `callgraph.incomplete=true`, `end_reason=desync` |
| Thread/process termination | Close live spans at stop time, `end_reason=shutdown` |
| Ring-buffer loss | Count and report; trace is incomplete |
| Export failure | Retry, then count failed and warn |
| Stray/bad event | Drop and count; no fabricated span |

Incomplete observation is a tracing-quality condition, not necessarily an
application error. Spans keep `status=UNSET`; the incompleteness is exposed as
attributes. No normal return timestamp is fabricated for an unfinished call.

## 10. CLI

```bash
# Existing human-readable output (default)
callgraph run -- ./my_app

# OTLP/gRPC to Jaeger on localhost:4317
callgraph run --exporter otlp -- ./my_app

# OTLP/HTTP/protobuf to localhost:4318
callgraph run --exporter otlp-http -- ./my_app

# Explicit endpoint and batching
callgraph attach -p 12345 \
    --exporter otlp \
    --endpoint localhost:4317 \
    --batch-size 512 \
    --flush-interval 1000

# Root sampling and filtering
callgraph run --exporter otlp --sample-rate 0.1 \
    --include 'Database::*' -- ./my_app

# File/offline paths
callgraph run --exporter otlp-json --export-file trace.otlp.json -- ./my_app
callgraph export --otel --input trace.log --output spans.json
callgraph export --flame --input trace.log --output stacks.folded
```

The default exporter is stdout. OTLP is explicitly enabled. `callgraph export`
has two mutually exclusive offline modes: `--otel` emits OTLP/JSON and
`--flame` emits folded stacks for flamegraph tools. `--batch-size` controls
OTLP batching; `--probe-batch-size` controls the `uprobe_multi` link batch
independently.

## 11. Jaeger visualization

Start a Jaeger version with an OTLP receiver (Jaeger v2, or all-in-one 1.35+),
then select the service in the UI:

```bash
docker run --rm -p 16686:16686 -p 4317:4317 -p 4318:4318 \
    jaegertracing/jaeger:latest

callgraph run --exporter otlp --service-name my_app -- ./my_app
```

Jaeger shows:

- hierarchical span trees;
- function durations;
- parent/child relationships;
- span/resource attributes;
- trace search and comparison.

Jaeger's timeline is not a globally ordered event log. The original text output
remains available for event-level inspection, and `--histogram` remains the
aggregated latency view.

## 12. Project structure

```
include/callgraph/
  clock_converter.h
  span_context.h
  span_generator.h
  span.h
  otel_exporter.h
  otlp_json.h
  otlp_proto.h
  trace_parser.h
  trace_metadata.h
src/
  clock_converter.cpp
  span_context.cpp
  span_generator.cpp
  otlp_json.cpp
  otlp_proto.cpp
  otel_exporter.cpp
  trace_parser.cpp
  trace_metadata.cpp
third_party/opentelemetry-proto/
```

## 13. Implementation status

| Stage | Status |
|---|---|
| Span generation | done: correct parent/child, recursion, desync, shutdown |
| OTLP export | done: gRPC, HTTP/protobuf, JSON file |
| Metadata | done: process/thread/module and DWARF source file/line |
| Performance | done: batching, bounded queue, retries, filters, root sampling |

Future work: official OpenTelemetry C++ SDK integration (the current exporter
uses generated OTLP protobuf messages and libcurl), OTLP/gRPC compression,
tail-sampling guidance in a Collector deployment, and richer trace-quality
metric export.

## 14. Architectural decision

The tracing engine stays independent of OpenTelemetry:

```
Shared tracing core
  libbpf / eBPF / ELF / DWARF
  Event collector + call-stack engine

Pluggable output backends
  Text backend       -> stdout/file
  OTel backend       -> OTLP -> Jaeger
```

This preserves the stable text output, keeps span generation independent of
eBPF instrumentation, and allows future backends such as Chrome Trace Event
Format, Perfetto, or a custom binary format.
