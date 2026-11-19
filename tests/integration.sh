#!/usr/bin/env bash
set -euo pipefail

BIN_DIR=${1:?usage: integration.sh /path/to/build-dir}
ROOT=$(cd "$(dirname "$0")/.." && pwd)
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

RUN=$(readlink -f "$BIN_DIR/callgraph-run")
ATTACH=$(readlink -f "$BIN_DIR/callgraph-attach")
EXPORT=$(readlink -f "$BIN_DIR/callgraph-export")
DISASM=$(readlink -f "$BIN_DIR/callgraph-disasm")
DISASM_BIN=$DISASM
WRAPPER="$ROOT/callgraph"

g++ -O0 -g -o "$TMP/simple" "$ROOT/examples/simple.cpp"
g++ -O0 -g -o "$TMP/recursive" "$ROOT/examples/recursive.cpp"
g++ -O0 -g -pthread -o "$TMP/multithread" "$ROOT/examples/multithread.cpp"
g++ -O0 -g -pthread -o "$TMP/tworoots" "$ROOT/examples/tworoots.cpp"
g++ -O0 -g -pthread -o "$TMP/kernel" "$ROOT/examples/kernel.cpp"
g++ -O0 -g -o "$TMP/pmu" "$ROOT/examples/pmu.cpp"
g++ -O0 -g -o "$TMP/exceptions" "$ROOT/examples/exceptions.cpp"
g++ -O0 -g -o "$TMP/longjmp" "$ROOT/examples/longjmp.cpp"
g++ -O0 -g -o "$TMP/ucontext" "$ROOT/examples/ucontext.cpp"

GO_BIN=
if command -v go >/dev/null 2>&1; then
    printf 'package main\n\nfunc main() {}\n' > "$TMP/gowarn.go"
    if (cd "$TMP" && go build -o "$TMP/gowarn" gowarn.go) >/dev/null 2>&1; then
        GO_BIN="$TMP/gowarn"
    fi
fi

echo "== dry run =="
dry=$("$RUN" --dry-run --regex \
    --root-scope '^(main|A[(]int[)]|B[(]int[)]|C[(]int[)])$' -- "$TMP/simple" 2>/dev/null)
echo "$dry" | grep -q 'main'
echo "$dry" | grep -q 'A(int)'
echo "$dry" | grep -q 'B(int)'

echo "== dry run: glob + exclude =="
dry=$("$RUN" --dry-run --root-scope '*' --exclude 'A*' -- "$TMP/simple" 2>/dev/null)
! echo "$dry" | grep -q 'A(int)'

echo "== removed --include =="
if "$RUN" --include '*' --dry-run -- "$TMP/simple" >/dev/null 2>&1; then
    echo "expected removed --include to fail" >&2
    exit 1
fi
if "$RUN" --scope '*' --dry-run -- "$TMP/simple" >/dev/null 2>&1; then
    echo "expected removed --scope to fail" >&2
    exit 1
fi
if "$RUN" --static-prune --dry-run -- "$TMP/simple" >/dev/null 2>&1; then
    echo "expected --static-prune to be unknown" >&2
    exit 1
fi

echo "== dry run: stripped binary fails =="
cp "$TMP/simple" "$TMP/stripped"
strip "$TMP/stripped"
if "$RUN" --dry-run -- "$TMP/stripped" >/dev/null 2>&1; then
    echo "expected a stripped binary to fail" >&2
    exit 1
fi

echo "== dry run: stripped binary with separate debug info =="
cp "$TMP/simple" "$TMP/detached"
objcopy --only-keep-debug "$TMP/detached" "$TMP/detached.debug"
strip --strip-all "$TMP/detached"
objcopy --add-gnu-debuglink="$TMP/detached.debug" "$TMP/detached"
dry=$("$RUN" --dry-run --regex --root-scope '^(main|A[(]int[)])$' \
    -- "$TMP/detached" 2>/dev/null)
echo "$dry" | grep -q 'main'
echo "$dry" | grep -q 'A(int)'

echo "== kernel CLI gating =="
for opt in "--sched" "--futex" "--io" "--block" "--memory" "--network" \
           "--events sched" "--events net" "--preset storage" \
           "--merge-window 1ms" "--require-events"; do
    # shellcheck disable=SC2086
    if "$RUN" $opt --dry-run -- "$TMP/simple" >/dev/null 2>&1; then
        echo "expected '$opt' without --kernel to fail" >&2
        exit 1
    fi
done
"$RUN" --kernel --dry-run -- "$TMP/simple" >/dev/null 2>&1
"$RUN" --kernel --events sched --preset storage \
    --merge-window 1ms --require-events --dry-run -- "$TMP/simple" \
    >/dev/null 2>&1
for preset in database cpu; do
    if "$RUN" --kernel --preset "$preset" --dry-run -- "$TMP/simple" \
        >/dev/null 2>&1; then
        echo "expected removed preset '$preset' to fail" >&2
        exit 1
    fi
done
if "$RUN" --kernel-events sched --dry-run -- "$TMP/simple" \
    >/dev/null 2>&1; then
    echo "expected the old --kernel-events name to fail" >&2
    exit 1
fi

echo "== PMU CLI gating =="
for opt in "--pmu cycles" "--events pmu" "--pmu-sampling 100000"; do
    # shellcheck disable=SC2086
    if "$RUN" $opt --dry-run -- "$TMP/simple" >/dev/null 2>&1; then
        echo "expected '$opt' without --kernel to fail" >&2
        exit 1
    fi
done
if "$RUN" --kernel --pmu-sampling 100000 --dry-run -- "$TMP/simple" \
    >/dev/null 2>&1; then
    echo "expected --pmu-sampling without --pmu to fail" >&2
    exit 1
fi
if "$RUN" --kernel --pmu no-such-counter --dry-run -- "$TMP/simple" \
    >/dev/null 2>&1; then
    echo "expected an unknown PMU counter to fail" >&2
    exit 1
fi
if "$RUN" --kernel --preset computation --dry-run -- "$TMP/simple" \
    2>&1 | grep -q 'PMU counting'; then
    echo "expected a preset not to enable PMU" >&2
    exit 1
fi
"$RUN" --kernel --pmu cycles,instructions --dry-run -- "$TMP/simple" \
    2>&1 | grep -q 'PMU counting: cycles,instructions'
"$RUN" --kernel --pmu cycles --pmu-sampling 100000 --dry-run \
    -- "$TMP/simple" 2>&1 | grep -q 'sampling every 100000 events'
"$RUN" --kernel --events pmu --dry-run -- "$TMP/simple" \
    2>&1 | grep -q 'PMU counting: cycles,instructions,cache-misses,branch-misses'
"$RUN" --kernel --events all --dry-run -- "$TMP/simple" \
    2>&1 | grep -q 'PMU counting: cycles'
"$RUN" --help | grep -q -- '--pmu <counters>'
"$RUN" --help | grep -q -- '--pmu-sampling <n>'

echo "== complete traces CLI gating =="
if "$RUN" --complete-traces --dry-run -- "$TMP/simple" \
    >/dev/null 2>&1; then
    echo "expected --complete-traces without an exporter to fail" >&2
    exit 1
fi
if "$RUN" --exporter otlp-json --export-file "$TMP/unused.json" \
    --trace-buffer-spans 1 --dry-run -- "$TMP/simple" >/dev/null 2>&1; then
    echo "expected trace-buffer options without --complete-traces to fail" >&2
    exit 1
fi
if "$RUN" --exporter otlp-json --export-file "$TMP/unused.json" \
    --outlier-latency-quantile 0.99 --dry-run -- "$TMP/simple" \
    >/dev/null 2>&1; then
    echo "expected --outlier-latency-quantile without --complete-traces to fail" >&2
    exit 1
fi
"$RUN" --exporter otlp-json --export-file "$TMP/unused.json" \
    --complete-traces --outlier-latency-quantile 0.99 --dry-run \
    -- "$TMP/simple" >/dev/null

echo "== help hierarchy =="
# grep -q closes the pipe as soon as it matches.  With pipefail enabled the
# writer's SIGPIPE would be reported as a test failure.
set +o pipefail
"$RUN" --help | grep -q '^Tracing options:'
"$RUN" --help | grep -q '^      --root-scope'
! "$RUN" --help | grep -q -- '--scope'
! "$RUN" --help | grep -q -- '--static-prune'
! "$RUN" --help | grep -q -- '--include-indirect'
"$RUN" --help | grep -q -- '--trace-depth'
"$RUN" --help | grep -q '<n> > 0 prunes probes along direct calls'
"$RUN" --help | grep -q '^Kernel event options (--kernel):'
"$RUN" --help | grep -q '^              latency           sched, futex, io, net syscalls$'
"$RUN" --help | grep -q '^              computation       sched, futex, direct reclaim, page faults$'
"$RUN" --help | grep -q '^              full              sched, futex, io, net syscalls, direct reclaim,$'
"$RUN" --help | grep -q '^              extended          sched, futex, io, block, net syscalls, direct reclaim,$'
"$RUN" --help | grep -q '^Live export options (--exporter):'
! "$RUN" --help | grep -q '^Offline export options:'
"$RUN" --help | grep -q '^General options:'
"$RUN" --help | grep -q '^  Correlated kernel events:'
"$RUN" --help | grep -q '^      --kernel'
"$RUN" --help | grep -q '^          --events'
"$RUN" --help | grep -q '^          --endpoint'
"$RUN" --help | grep -q '^          --complete-traces'
"$RUN" --help | grep -q '^              --trace-buffer-bytes <size>'
"$RUN" --help | grep -q '^              --outlier-latency-quantile <quantile>'
"$RUN" --help | grep -q '^      --ingest-sample-rate <rate>'
"$RUN" --help | grep -q '^      --log-rate-limit <n>'
"$RUN" --help | grep -q 'limit stdout user and kernel event lines'
"$EXPORT" --help | grep -q '^      --otel'
"$EXPORT" --help | grep -q '^      --flame'
"$EXPORT" --otel --help | grep -q '^          --endpoint'
"$EXPORT" --otel --help | grep -q '^          --complete-traces'
"$EXPORT" --otel --help | grep -q '^              --outlier-latency-quantile <quantile>'
"$EXPORT" --flame --help | grep -q '^      --flame'
"$EXPORT" --static --help | grep -q '^      --static'
"$EXPORT" --static --help | grep -q '^          --static-graph <file>'
"$EXPORT" --static --help | grep -q '^          --root-scope <glob>'
"$EXPORT" --static --help | grep -q 'callgraph-export --static --static-graph <file>'
"$EXPORT" --static --help | grep -q 'required when callgraph-export --static is run directly'
"$EXPORT" --static --help | grep -q 'callgraph export --static --all-modules ./app'
"$DISASM_BIN" --help | grep -q '^usage: callgraph-disasm \[<options>\] <module>'
"$DISASM_BIN" --help | grep -q 'The callgraph wrapper runs callgraph-disasm automatically'
# Mode pages are narrowed: no options from the other modes.
! "$EXPORT" --static --help | grep -q -- '--otel'
! "$EXPORT" --static --help | grep -q -- '--endpoint'
! "$EXPORT" --otel --help | grep -q -- '--static-graph'
! "$EXPORT" --otel --help | grep -q '^      --flame'
! "$EXPORT" --flame --help | grep -q -- '--endpoint'
! "$EXPORT" --flame --help | grep -q -- '--static-graph'
# The program-level page still lists every mode.
"$EXPORT" --help | grep -q '^      --otel'
"$EXPORT" --help | grep -q '^      --static'
"$EXPORT" --help | grep -q '^      --flame'
"$EXPORT" --help | grep -q 'callgraph export --static --all-modules ./app'
# The run/attach page points at the exporter instead of duplicating it.
"$RUN" --help | grep -q "Offline conversion: run 'callgraph export --help'"
"$RUN" --help > "$TMP/help-run.txt"
"$RUN" -h > "$TMP/help-run-short.txt"
cmp "$TMP/help-run.txt" "$TMP/help-run-short.txt"
"$ATTACH" --help > "$TMP/help-attach.txt"
"$EXPORT" --help > "$TMP/help-export.txt"
grep -q '^  callgraph-run \[<options>\] -- <program>' "$TMP/help-run.txt"
grep -q '^  callgraph-attach \[<options>\] -p <pid>' "$TMP/help-attach.txt"
grep -q '^  callgraph-export --otel|--flame --input <trace>' "$TMP/help-export.txt"
grep -q 'The callgraph wrapper runs callgraph-disasm' "$TMP/help-run.txt"
grep -q 'generated JSON facts automatically' "$TMP/help-run.txt"
! grep -q -- '--kernel' "$TMP/help-export.txt"
! grep -q '^Offline export options:' "$TMP/help-run.txt"
! grep -q -- '--exporter' "$TMP/help-export.txt"
set -o pipefail

echo "== OTLP offline conversion =="
cat > "$TMP/otel.trace" <<'EOF'
2026-11-12T10:00:00.000000000+00:00 100 : 0 -> main
2026-11-12T10:00:00.000001000+00:00 100 : 1 -> C(int)
2026-11-12T10:00:00.000002000+00:00 100 : 2 -> B(int)
2026-11-12T10:00:00.000003000+00:00 100 : 2 <- B(int)
2026-11-12T10:00:00.000004000+00:00 100 : 1 <- C(int)
2026-11-12T10:00:00.000005000+00:00 100 : 0 <- main
EOF
"$EXPORT" --otel --input "$TMP/otel.trace" --output "$TMP/otel.json" \
    --service-name demo --trace-id-seed 1234 2>"$TMP/otel.err"
grep -q 'converted 6 events' "$TMP/otel.err"
grep -q '3 OTLP span(s)' "$TMP/otel.err"
"$EXPORT" --otel --input "$TMP/otel.trace" \
    --output "$TMP/complete-out.json" --complete-traces \
    2>"$TMP/complete.err"
grep -q 'trace buffer: 1 completed' "$TMP/complete.err"
grep -q '"resourceSpans"' "$TMP/complete-out.json"
if "$EXPORT" --otel --input "$TMP/otel.trace" \
    --output "$TMP/outlier-only.json" --outlier-latency-quantile 0.99 \
    >/dev/null 2>&1; then
    echo "expected offline --outlier-latency-quantile without --complete-traces to fail" >&2
    exit 1
fi
"$EXPORT" --otel --input "$TMP/otel.trace" \
    --output "$TMP/outlier.json" --complete-traces \
    --outlier-latency-quantile 0.99 2>"$TMP/outlier.err"
grep -q 'outlier sampling' "$TMP/outlier.err"
grep -q 'callgraph.quantile' "$TMP/outlier.json"
: >"$TMP/warmup.trace"
for i in $(seq 0 99); do
    tid=$((100 + i))
    base=$((i * 1000000))
    printf '2026-11-12T10:00:00.%09d+00:00 %d : 0 -> main\n' \
        "$base" "$tid" >>"$TMP/warmup.trace"
    printf '2026-11-12T10:00:00.%09d+00:00 %d : 1 -> A(int)\n' \
        "$((base + 200))" "$tid" >>"$TMP/warmup.trace"
    printf '2026-11-12T10:00:00.%09d+00:00 %d : 1 <- A(int)\n' \
        "$((base + 400))" "$tid" >>"$TMP/warmup.trace"
    printf '2026-11-12T10:00:00.%09d+00:00 %d : 0 <- main\n' \
        "$((base + 1000))" "$tid" >>"$TMP/warmup.trace"
done
"$EXPORT" --otel --input "$TMP/warmup.trace" \
    --output "$TMP/warmup.json" --complete-traces \
    --outlier-latency-quantile 0.9 --sample-rate 0 2>"$TMP/warmup.err"
grep -q 'trace buffer: 100 completed, 0 exported' "$TMP/warmup.err"
grep -q '100 trace(s) seen' "$TMP/warmup.err"
grep -q '0 trace(s) reported' "$TMP/warmup.err"
grep -q '0 span(s) reported' "$TMP/warmup.err"
grep -q 'threshold pending' "$TMP/warmup.err"
if grep -q 'filtered' "$TMP/warmup.err"; then
    echo "outlier sampling must report selected traces, not filtered ones" >&2
    exit 1
fi
grep -q '"resourceSpans"' "$TMP/otel.json"
grep -q '"service.name","value":{"stringValue":"demo"}' "$TMP/otel.json"
grep -q '"name":"C(int)"' "$TMP/otel.json"
cat > "$TMP/args-offline.trace" <<'EOF'
2026-11-12T10:00:00.000000000+00:00 100 : 0 -> main
2026-11-12T10:00:00.000001000+00:00 100 : 1 -> C(int) (x=3)
2026-11-12T10:00:00.000002000+00:00 100 : 1 <- C(int)
2026-11-12T10:00:00.000003000+00:00 100 : 0 <- main
EOF
"$EXPORT" --otel --input "$TMP/args-offline.trace" \
    --output "$TMP/args-offline.json" --show-args 2>/dev/null
grep -q '"key":"code.arguments"' "$TMP/args-offline.json"
grep -q '"stringValue":"(x=3)"' "$TMP/args-offline.json"
if "$EXPORT" --otel --input "$TMP/args-offline.trace" \
    --output "$TMP/args-unused.json" --input-show-args >/dev/null 2>&1; then
    echo "expected --input-show-args to be removed" >&2
    exit 1
fi
"$EXPORT" --otel --input "$TMP/otel.trace" --output "$TMP/sampled.json" \
    --sample-rate 0 2>/dev/null
if command -v python3 >/dev/null 2>&1; then
    python3 - "$TMP/sampled.json" <<'PY'
import json, sys
doc = json.load(open(sys.argv[1]))
assert len(doc["resourceSpans"][0]["scopeSpans"][0]["spans"]) == 0
PY
fi

echo "== OTLP drop reasons =="
if command -v python3 >/dev/null 2>&1; then
    python3 - "$EXPORT" "$TMP" <<'PY'
import http.server, os, re, subprocess, sys, threading, time

binary, tmp = sys.argv[1:3]
trace = os.path.join(tmp, "drop.trace")
with open(trace, "w") as f:
    f.write("2026-11-14T00:00:00.000000000+00:00 1 : 0 -> root\n")
    for i in range(40):
        stamp = f"2026-11-14T00:00:00.{i + 1:09d}+00:00"
        f.write(f"{stamp} 1 : 1 -> child{i}\n")
        f.write(f"{stamp} 1 : 1 <- child{i}\n")
    f.write("2026-11-14T00:00:01.000000000+00:00 1 : 0 <- root\n")

class Handler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        n = int(self.headers.get("Content-Length", "0"))
        self.rfile.read(n)
        time.sleep(0.1)
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b"{}")
    def log_message(self, *args):
        pass

server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
thread = threading.Thread(target=server.serve_forever, daemon=True)
thread.start()
try:
    result = subprocess.run(
        [binary, "--otel", "--input", trace,
         "--endpoint", f"http://127.0.0.1:{server.server_port}",
         "--queue-spans", "1", "--batch-size", "1",
         "--flush-interval", "10", "--timeout-ms", "1000"],
        capture_output=True, text=True, timeout=60)
finally:
    server.shutdown()
    thread.join(timeout=5)
    server.server_close()

assert result.returncode == 0, result.stderr
assert "OTLP drop reasons:" in result.stderr, result.stderr
assert re.search(r"queue-spans-full=[1-9][0-9]*", result.stderr), result.stderr
assert re.search(r"(\d+) dropped", result.stderr), result.stderr
PY
fi

echo "== OTLP offline depth: same-depth entries are siblings =="
cat > "$TMP/depth.trace" <<'EOF'
2026-11-12T10:00:00.000000000+00:00 100 : 0 -> pq_getmsgstring
2026-11-12T10:00:00.000001000+00:00 100 : 0 -> pg_client_to_server
2026-11-12T10:00:00.000002000+00:00 100 : 0 -> pg_any_to_server
2026-11-12T10:00:00.000003000+00:00 100 : 1 -> pg_verify_mbstr
2026-11-12T10:00:00.000004000+00:00 100 : 1 <- pg_verify_mbstr
2026-11-12T10:00:00.000005000+00:00 100 : 0 <- pg_any_to_server
2026-11-12T10:00:00.000006000+00:00 100 : 0 -> pq_getmsgend
2026-11-12T10:00:00.000007000+00:00 100 : 0 <- pq_getmsgend
EOF
"$EXPORT" --otel --input "$TMP/depth.trace" --output "$TMP/depth.json" \
    --trace-id-seed 7 2>/dev/null
if command -v python3 >/dev/null 2>&1; then
    python3 - "$TMP/depth.json" <<'PY'
import json, sys
doc = json.load(open(sys.argv[1]))
spans = doc["resourceSpans"][0]["scopeSpans"][0]["spans"]
by_name = {s["name"]: s for s in spans}
# A depth-0 entry after another depth-0 entry is a sibling root, not a child.
for name in ("pq_getmsgstring", "pg_client_to_server", "pg_any_to_server",
             "pq_getmsgend"):
    assert by_name[name].get("parentSpanId") is None, (name, by_name[name])
# A depth+1 call still nests under its caller.
assert by_name["pg_verify_mbstr"]["parentSpanId"] == \
       by_name["pg_any_to_server"]["spanId"], by_name
PY
fi

echo "== OTLP offline boot-second anchor =="
cat > "$TMP/boot.trace" <<'EOF'
100.000000000 7 : 0 -> main
100.000001000 7 : 1 -> C(int)
100.000002000 7 : 1 <- C(int)
100.000003000 7 : 0 <- main
EOF
"$EXPORT" --otel --input "$TMP/boot.trace" --output "$TMP/boot.json" \
    --assume-local-capture 2>"$TMP/boot.err"
grep -q 'assuming the trace was captured on this host' "$TMP/boot.err"
if command -v python3 >/dev/null 2>&1; then
    python3 - "$TMP/boot.json" <<'PY'
import json, sys
doc = json.load(open(sys.argv[1]))
spans = doc["resourceSpans"][0]["scopeSpans"][0]["spans"]
assert len(spans) == 2
assert all(int(s["startTimeUnixNano"]) > 10**18 for s in spans), spans
PY
fi

echo "== Flamegraph export =="
"$EXPORT" --flame --input "$TMP/boot.trace" \
    --output "$TMP/boot.folded" 2>"$TMP/flame.err"
grep -q 'converted .* events into .* folds' "$TMP/flame.err"
grep -qx 'main 1' "$TMP/boot.folded"
grep -qx 'main;C(int) 1' "$TMP/boot.folded"
cat > "$TMP/flame-incomplete.trace" <<'EOF'
100.000000000 7 : 0 -> main
100.000001000 7 : 1 -> A(int)
100.000002000 7 : 0 <- main
EOF
"$EXPORT" --flame --input "$TMP/flame-incomplete.trace" \
    --output "$TMP/flame-incomplete.folded" 2>/dev/null
grep -Fqx 'main;A(int);[incomplete] 1' "$TMP/flame-incomplete.folded"
grep -qx 'main 1' "$TMP/flame-incomplete.folded"
"$EXPORT" --flame --help | grep -q 'flamegraph.pl'
if "$EXPORT" --flame --metadata "$TMP/otel.meta" \
    --input "$TMP/boot.trace" >/dev/null 2>&1; then
    echo "expected OTel options to be rejected with --flame" >&2
    exit 1
fi
if "$EXPORT" otel --input "$TMP/boot.trace" >/dev/null 2>&1; then
    echo "expected the old 'export otel' form to be rejected" >&2
    exit 1
fi

if command -v python3 >/dev/null 2>&1; then
    echo "== OTLP JSON validation and HTTP + gzip export =="
    python3 - "$EXPORT" "$TMP/otel.json" "$TMP/otel.trace" <<'PY'
import gzip, http.server, json, subprocess, sys, threading, time

binary, json_path, trace_path = sys.argv[1:4]
doc = json.load(open(json_path))
spans = doc["resourceSpans"][0]["scopeSpans"][0]["spans"]
assert len(spans) == 3, spans
by_name = {s["name"]: s for s in spans}
assert "main" in by_name and "C(int)" in by_name and "B(int)" in by_name
assert by_name["main"].get("parentSpanId") is None
assert by_name["C(int)"]["parentSpanId"] == by_name["main"]["spanId"]
assert by_name["B(int)"]["parentSpanId"] == by_name["C(int)"]["spanId"]
assert len({s["traceId"] for s in spans}) == 1

requests = []
class Handler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        n = int(self.headers.get("Content-Length", "0"))
        data = self.rfile.read(n)
        if self.headers.get("Content-Encoding") == "gzip":
            data = gzip.decompress(data)
        requests.append({
            "path": self.path,
            "header": self.headers.get("X-Test"),
            "encoding": self.headers.get("Content-Encoding"),
            "body": data,
        })
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b"{}")
    def log_message(self, *args):
        pass

server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
server.timeout = 0.5
thread = threading.Thread(target=server.serve_forever, daemon=True)
thread.start()
port = server.server_port
result = subprocess.run(
    [binary, "--otel", "--input", trace_path,
     "--endpoint", f"http://127.0.0.1:{port}",
     "--compression", "gzip", "--header", "X-Test=value"],
    capture_output=True, text=True, timeout=60)

deadline = time.time() + 5
received_spans = 0
while time.time() < deadline:
    received_spans = sum(
        len(json.loads(r["body"])["resourceSpans"][0]["scopeSpans"][0]["spans"])
        for r in requests)
    if received_spans >= 3:
        break
    time.sleep(0.02)

server.shutdown()
thread.join(timeout=5)
server.server_close()
assert result.returncode == 0, result.stderr
assert "3 OTLP span(s)" in result.stderr, result.stderr
assert requests, "mock OTLP server received no request"
for request in requests:
    assert request["path"] == "/v1/traces", request
    assert request["header"] == "value", request
    assert request["encoding"] == "gzip", request
assert received_spans == 3, received_spans
PY
fi

if [ -n "$GO_BIN" ]; then
    echo "== Go binary warning =="
    "$RUN" --dry-run --regex --root-scope '^main\.main$' -- "$GO_BIN" \
        >/dev/null 2>"$TMP/gowarn.err"
    grep -q 'Go binary' "$TMP/gowarn.err"
    grep -q -- '--return-mode=ret' "$TMP/gowarn.err"

    "$DISASM" "$GO_BIN" -o "$TMP/gowarn.json"
    "$RUN" --dry-run --return-mode ret --regex \
        --static-graph "$TMP/gowarn.json" \
        --root-scope '^main\.main$' -- "$GO_BIN" \
        >/dev/null 2>"$TMP/gowarn_ret.err"
    grep -q 'nesting unreliable' "$TMP/gowarn_ret.err"

    if (cd "$TMP" && go build -ldflags="-s -w" -o "$TMP/gowarn_stripped" \
            gowarn.go) >/dev/null 2>&1; then
        if "$RUN" --dry-run -- "$TMP/gowarn_stripped" \
                >/dev/null 2>"$TMP/gowarn_stripped.err"; then
            echo "expected a stripped Go binary to fail" >&2
            exit 1
        fi
        grep -q 'Go binary without a usable symbol table' \
            "$TMP/gowarn_stripped.err"
    fi
fi

echo "== link guard: the tracers have no disassembler =="
for tracer in "$RUN" "$ATTACH" "$EXPORT"; do
    if command -v ldd >/dev/null 2>&1; then
        if ldd "$tracer" 2>/dev/null | grep -Eqi 'libopcodes|libbfd'; then
            echo "$tracer must not link libopcodes/libbfd" >&2
            exit 1
        fi
    fi
    if command -v nm >/dev/null 2>&1; then
        if nm -D "$tracer" 2>/dev/null \
            | grep -Eq 'init_disassemble_info|disassembler'; then
            echo "$tracer must not reference the disassembler API" >&2
            exit 1
        fi
    fi
done
# The offline converter must not drag in the live tracer stack.
if command -v nm >/dev/null 2>&1; then
    if nm -D "$EXPORT" 2>/dev/null | grep -Eq ' bpf_|uprobe'; then
        echo "callgraph-export must not reference libbpf/uprobes" >&2
        exit 1
    fi
fi

echo "== static facts generation =="
if [ ! -x "$DISASM" ]; then
    echo "callgraph-disasm not found at $DISASM" >&2
    exit 1
fi
"$DISASM" "$TMP/simple" -o "$TMP/simple.json"
grep -q '"format":"callgraph-static-graph"' "$TMP/simple.json"
grep -q '"version":1' "$TMP/simple.json"
grep -q '"name":"main"' "$TMP/simple.json"
grep -q '"return_offsets":\[' "$TMP/simple.json"

"$DISASM" --all-modules "$TMP/recursive" -o "$TMP/recursive.json"
grep -q '"name":"factorial' "$TMP/recursive.json"

echo "== static export from facts =="
"$EXPORT" --static --static-graph "$TMP/simple.json" \
    >"$TMP/static.txt" 2>"$TMP/static.err"
grep -qx 'main' "$TMP/static.txt"
grep -q '└── C(int)' "$TMP/static.txt"
grep -q '├── B(int)' "$TMP/static.txt"
grep -q '│   └── A(int)' "$TMP/static.txt"
grep -q '^    └── A(int)$' "$TMP/static.txt"
# Root sections are separated by a blank line.
grep -q '^$' "$TMP/static.txt"

"$EXPORT" --static --static-graph "$TMP/simple.json" \
    -o "$TMP/static_file.txt" 2>/dev/null
cmp "$TMP/static.txt" "$TMP/static_file.txt"
"$EXPORT" --static --static-graph "$TMP/simple.json" -o - 2>/dev/null \
    | cmp - "$TMP/static.txt"

scoped=$("$EXPORT" --static --static-graph "$TMP/simple.json" \
    --root-scope 'C*' 2>/dev/null)
[ "$(printf '%s\n' "$scoped" | head -n 1)" = "C(int)" ]
! printf '%s\n' "$scoped" | grep -qx 'main'

"$EXPORT" --static --static-graph "$TMP/simple.json" \
    --regex --root-scope '^C' 2>/dev/null | grep -qx 'C(int)'

"$EXPORT" --static --static-graph "$TMP/recursive.json" \
    --root-scope 'factorial*' 2>/dev/null | grep -q '\[recursive\]'

if "$EXPORT" --static --static-graph "$TMP/simple.json" \
        --root-scope 'no_such_function_xyz' >/dev/null 2>&1; then
    echo "expected an unmatched --root-scope to fail" >&2
    exit 1
fi

# --all-modules: a tiny shared object plus its DT_NEEDED dependency.
cat > "$TMP/static_dep.c" <<'EOF'
int dep_leaf(int x) { return x + 1; }
int dep_root(int x) { return dep_leaf(x); }
EOF
cat > "$TMP/static_main.c" <<'EOF'
extern int dep_root(int);
int main_root(int x) { return dep_root(x); }
int main(void) { return main_root(1); }
EOF
gcc -shared -fPIC -nostdlib -o "$TMP/libstaticdep.so" "$TMP/static_dep.c"
gcc -shared -fPIC -nostdlib -o "$TMP/libstaticmain.so" \
    "$TMP/static_main.c" -L"$TMP" -lstaticdep -Wl,-rpath,"$TMP"

"$DISASM" --all-modules "$TMP/libstaticmain.so" -o "$TMP/all.json"
all=$("$EXPORT" --static --static-graph "$TMP/all.json" 2>/dev/null)
printf '%s\n' "$all" | grep -qx "== $TMP/libstaticmain.so =="
printf '%s\n' "$all" | grep -qx "== $TMP/libstaticdep.so =="
printf '%s\n' "$all" | grep -qx 'dep_leaf'

# The filter applies per module; dependencies without a match are skipped.
all=$("$EXPORT" --static --static-graph "$TMP/all.json" \
    --root-scope 'main_root' 2>/dev/null)
printf '%s\n' "$all" | grep -qx "== $TMP/libstaticmain.so =="
! printf '%s\n' "$all" | grep -q "== $TMP/libstaticdep.so =="

echo "== static facts CLI gating =="
echo "not an elf" > "$TMP/notelf"
if "$DISASM" "$TMP/notelf" >/dev/null 2>&1; then
    echo "expected a non-ELF disasm input to fail" >&2
    exit 1
fi
if "$DISASM" >/dev/null 2>&1; then
    echo "expected callgraph-disasm without MODULE to fail" >&2
    exit 1
fi
if "$DISASM" --format tsv "$TMP/simple" >/dev/null 2>&1; then
    echo "expected the removed --format option to fail" >&2
    exit 1
fi

if "$EXPORT" --static >/dev/null 2>&1; then
    echo "expected export --static without facts to fail" >&2
    exit 1
fi
if "$EXPORT" --static --static-graph "$TMP/simple.json" "$TMP/simple" \
        >/dev/null 2>&1; then
    echo "expected a positional MODULE with --static to fail" >&2
    exit 1
fi
if "$EXPORT" --static --static-graph "$TMP/simple.json" \
        --input trace.log >/dev/null 2>&1; then
    echo "expected --input with --static to fail" >&2
    exit 1
fi
if "$EXPORT" --static --static-graph "$TMP/simple.json" --otel \
        >/dev/null 2>&1; then
    echo "expected --static --otel to fail" >&2
    exit 1
fi
if "$EXPORT" --static --static-graph "$TMP/simple.json" \
        --all-modules >/dev/null 2>&1; then
    echo "expected --all-modules with export to fail" >&2
    exit 1
fi
if "$EXPORT" --otel --input trace.log --output out.json \
        --static-graph "$TMP/simple.json" >/dev/null 2>&1; then
    echo "expected --static-graph with --otel to fail" >&2
    exit 1
fi
if "$EXPORT" --static --static-graph "$TMP/simple.json" \
        --exclude 'C*' >/dev/null 2>&1; then
    echo "expected --exclude with --static to fail" >&2
    exit 1
fi
if "$EXPORT" --static --static-graph "$TMP/notelf" \
        >/dev/null 2>&1; then
    echo "expected malformed facts to fail" >&2
    exit 1
fi
printf '%s\n' \
    '{"format":"callgraph-static-graph","version":9,"modules":[]}' \
    > "$TMP/future.json"
if "$EXPORT" --static --static-graph "$TMP/future.json" \
        >/dev/null 2>&1; then
    echo "expected an unsupported facts version to fail" >&2
    exit 1
fi

echo "== ret mode requires facts =="
if "$RUN" --return-mode=ret --dry-run -- "$TMP/simple" \
        >/dev/null 2>"$TMP/ret.err"; then
    echo "expected --return-mode=ret without facts to fail" >&2
    exit 1
fi
grep -q -- '--return-mode=ret requires --static-graph' "$TMP/ret.err"
"$RUN" --return-mode=ret --static-graph "$TMP/simple.json" \
    --dry-run -- "$TMP/simple" >/dev/null 2>&1

echo "== callgraph =="
CALLGRAPH_RUN="$RUN" CALLGRAPH_ATTACH="$ATTACH" \
    CALLGRAPH_EXPORT="$EXPORT" CALLGRAPH_DISASM="$DISASM_BIN" \
    "$WRAPPER" disasm "$TMP/simple" -o "$TMP/wrapper.json"
grep -q '"format":"callgraph-static-graph"' "$TMP/wrapper.json"

CALLGRAPH_RUN="$RUN" CALLGRAPH_ATTACH="$ATTACH" \
    CALLGRAPH_EXPORT="$EXPORT" CALLGRAPH_DISASM="$DISASM_BIN" \
    "$WRAPPER" export --static --static-graph "$TMP/wrapper.json" \
    >"$TMP/wrapper.txt" 2>/dev/null
grep -qx 'main' "$TMP/wrapper.txt"

CALLGRAPH_RUN="$RUN" CALLGRAPH_ATTACH="$ATTACH" \
    CALLGRAPH_EXPORT="$EXPORT" CALLGRAPH_DISASM="$DISASM_BIN" \
    "$WRAPPER" export --static "$TMP/simple" >"$TMP/wrapper2.txt" 2>/dev/null
cmp "$TMP/wrapper.txt" "$TMP/wrapper2.txt"

# The removed wrapper options are rejected by the tracer/exporter.
for removed in --no-graph "--graph-in=$TMP/wrapper.json" \
               "--graph-out=$TMP/gone.json"; do
    if CALLGRAPH_RUN="$RUN" CALLGRAPH_ATTACH="$ATTACH" \
            CALLGRAPH_EXPORT="$EXPORT" CALLGRAPH_DISASM="$DISASM_BIN" \
            "$WRAPPER" run "$removed" --trace-depth 1 --dry-run \
            -- "$TMP/simple" >/dev/null 2>&1; then
        echo "expected removed wrapper option $removed to fail" >&2
        exit 1
    fi
done
if CALLGRAPH_RUN="$RUN" CALLGRAPH_ATTACH="$ATTACH" \
        CALLGRAPH_EXPORT="$EXPORT" CALLGRAPH_DISASM="$DISASM_BIN" \
        "$WRAPPER" export --static --no-graph "$TMP/simple" \
        >/dev/null 2>&1; then
    echo "expected removed --no-graph to fail" >&2
    exit 1
fi

CALLGRAPH_RUN="$RUN" CALLGRAPH_ATTACH="$ATTACH" \
    CALLGRAPH_EXPORT="$EXPORT" CALLGRAPH_DISASM="$DISASM_BIN" \
    "$WRAPPER" run --dry-run -- "$TMP/simple" >/dev/null 2>&1
CALLGRAPH_RUN="$RUN" CALLGRAPH_ATTACH="$ATTACH" \
    CALLGRAPH_EXPORT="$EXPORT" CALLGRAPH_DISASM="$DISASM_BIN" \
    "$WRAPPER" run --trace-depth 1 --dry-run -- "$TMP/simple" \
    >"$TMP/wrapper-dry.txt" 2>"$TMP/wrapper-dry.err"
grep -q 'main' "$TMP/wrapper-dry.txt"
# A user-supplied --static-graph suppresses generation and is inserted before
# the "--" separator.
CALLGRAPH_RUN="$RUN" CALLGRAPH_ATTACH="$ATTACH" \
    CALLGRAPH_EXPORT="$EXPORT" CALLGRAPH_DISASM="$DISASM_BIN" \
    "$WRAPPER" run --static-graph "$TMP/wrapper.json" --trace-depth 1 \
    --dry-run -- "$TMP/simple" >"$TMP/wrapper-dry2.txt" 2>/dev/null
cmp "$TMP/wrapper-dry.txt" "$TMP/wrapper-dry2.txt"

echo "== callgraph: help and version are side-effect free =="
CALLGRAPH_RUN="$RUN" CALLGRAPH_ATTACH="$ATTACH" \
    CALLGRAPH_EXPORT="$EXPORT" CALLGRAPH_DISASM="$DISASM_BIN" \
    "$WRAPPER" --help | grep -q '^usage: callgraph <command>'
CALLGRAPH_RUN="$RUN" CALLGRAPH_ATTACH="$ATTACH" \
    CALLGRAPH_EXPORT="$EXPORT" CALLGRAPH_DISASM="$DISASM_BIN" \
    "$WRAPPER" run --help | grep -q '^  callgraph-run \[<options>\]'
CALLGRAPH_RUN="$RUN" CALLGRAPH_ATTACH="$ATTACH" \
    CALLGRAPH_EXPORT="$EXPORT" CALLGRAPH_DISASM="$DISASM_BIN" \
    "$WRAPPER" attach --help | grep -q '^  callgraph-attach \[<options>\]'
CALLGRAPH_RUN="$RUN" CALLGRAPH_ATTACH="$ATTACH" \
    CALLGRAPH_EXPORT="$EXPORT" CALLGRAPH_DISASM="$DISASM_BIN" \
    "$WRAPPER" export --otel --help | grep -q -- '--endpoint'
CALLGRAPH_RUN="$RUN" CALLGRAPH_ATTACH="$ATTACH" \
    CALLGRAPH_EXPORT="$EXPORT" CALLGRAPH_DISASM="$DISASM_BIN" \
    "$WRAPPER" export --static --help | grep -q -- '--static-graph'
CALLGRAPH_RUN="$RUN" CALLGRAPH_ATTACH="$ATTACH" \
    CALLGRAPH_EXPORT="$EXPORT" CALLGRAPH_DISASM="$DISASM_BIN" \
    "$WRAPPER" export --static --version | grep -q '^callgraph-export '

echo "== callgraph: temporary facts are cleaned up =="
mkdir -p "$TMP/factstmp"
assert_factstmp_empty() {
    if [ -n "$(ls -A "$TMP/factstmp")" ]; then
        echo "temporary facts were not removed: $(ls -A "$TMP/factstmp")" >&2
        exit 1
    fi
}

TMPDIR="$TMP/factstmp" CALLGRAPH_RUN="$RUN" CALLGRAPH_ATTACH="$ATTACH" \
    CALLGRAPH_EXPORT="$EXPORT" CALLGRAPH_DISASM="$DISASM_BIN" \
    "$WRAPPER" run --trace-depth 1 --dry-run -- "$TMP/simple" \
    >/dev/null 2>&1
assert_factstmp_empty

TMPDIR="$TMP/factstmp" CALLGRAPH_RUN="$RUN" CALLGRAPH_ATTACH="$ATTACH" \
    CALLGRAPH_EXPORT="$EXPORT" CALLGRAPH_DISASM="$DISASM_BIN" \
    "$WRAPPER" export --static "$TMP/simple" >/dev/null 2>&1
assert_factstmp_empty

# A generator failure must still remove the directory.
if TMPDIR="$TMP/factstmp" CALLGRAPH_RUN="$RUN" CALLGRAPH_ATTACH="$ATTACH" \
        CALLGRAPH_EXPORT="$EXPORT" CALLGRAPH_DISASM="$DISASM_BIN" \
        "$WRAPPER" export --static "$TMP/notelf" >/dev/null 2>&1; then
    echo "expected a non-ELF static export to fail" >&2
    exit 1
fi
assert_factstmp_empty

# A user-supplied --static-graph creates nothing.
TMPDIR="$TMP/factstmp" CALLGRAPH_RUN="$RUN" CALLGRAPH_ATTACH="$ATTACH" \
    CALLGRAPH_EXPORT="$EXPORT" CALLGRAPH_DISASM="$DISASM_BIN" \
    "$WRAPPER" run --static-graph "$TMP/wrapper.json" --trace-depth 1 \
    --dry-run -- "$TMP/simple" >/dev/null 2>&1
assert_factstmp_empty

# The child's exit status survives the wait-and-clean path.
status=0
TMPDIR="$TMP/factstmp" CALLGRAPH_RUN="$RUN" CALLGRAPH_ATTACH="$ATTACH" \
    CALLGRAPH_EXPORT="$EXPORT" CALLGRAPH_DISASM="$DISASM_BIN" \
    "$WRAPPER" run --trace-depth 1 --dry-run --bogus -- "$TMP/simple" \
    >/dev/null 2>&1 || status=$?
[ "$status" -eq 2 ]
assert_factstmp_empty

echo "== callgraph: resolves its real path =="
# A symlinked wrapper must find the binaries next to the real script, not
# next to the link.
mkdir -p "$TMP/install" "$TMP/link" "$TMP/broken"
cp "$WRAPPER" "$TMP/install/callgraph"
ln -s "$RUN" "$TMP/install/callgraph-run"
ln -s "$ATTACH" "$TMP/install/callgraph-attach"
ln -s "$EXPORT" "$TMP/install/callgraph-export"
ln -s "$DISASM_BIN" "$TMP/install/callgraph-disasm"
ln -s ../install/callgraph "$TMP/link/callgraph"

"$TMP/link/callgraph" disasm "$TMP/simple" -o "$TMP/self.json"
grep -q '"format":"callgraph-static-graph"' "$TMP/self.json"

# The same through PATH, from an unrelated working directory.
(
    cd "$TMP" || exit 1
    PATH="$TMP/link:$PATH" callgraph --version >"$TMP/self-version.txt"
)
grep -q '^callgraph-run ' "$TMP/self-version.txt"
grep -q '^callgraph-attach ' "$TMP/self-version.txt"
grep -q '^callgraph-export ' "$TMP/self-version.txt"
grep -q '^callgraph-disasm ' "$TMP/self-version.txt"

# A missing sibling is reported against the real directory.
cp "$WRAPPER" "$TMP/broken/callgraph"
ln -s "$RUN" "$TMP/broken/callgraph-run"
ln -s "$ATTACH" "$TMP/broken/callgraph-attach"
ln -s "$EXPORT" "$TMP/broken/callgraph-export"
if "$TMP/broken/callgraph" disasm "$TMP/simple" \
        >/dev/null 2>"$TMP/broken.err"; then
    echo "expected a missing callgraph-disasm to fail" >&2
    exit 1
fi
grep -q 'callgraph-disasm not found' "$TMP/broken.err"

if [ "$(id -u)" -ne 0 ]; then
    echo "== tracing tests skipped (not root) =="
    exit 0
fi

echo "== trace simple =="
"$RUN" -o "$TMP/simple.trace" --regex \
    --root-scope '^(main|A[(]int[)]|B[(]int[)]|C[(]int[)])$' -- "$TMP/simple" \
    >/dev/null 2>"$TMP/simple.err"
grep -Eq '^[0-9]+\.[0-9]{9} [0-9]+ : 0 -> main' "$TMP/simple.trace"
grep -q ' : 1 -> C(int)' "$TMP/simple.trace"
grep -q ' : 2 -> B(int)' "$TMP/simple.trace"
grep -q ' : 3 -> A(int)' "$TMP/simple.trace"
grep -q ' : 3 <- A(int)' "$TMP/simple.trace"
grep -q ' : 0 <- main' "$TMP/simple.trace"
grep -q '0 lost' "$TMP/simple.err"

echo "== ingest sampling and log rate limit =="
"$RUN" -o "$TMP/ingest.trace" --ingest-sample-rate 0 --regex \
    --root-scope '^(main|A[(]int[)]|B[(]int[)]|C[(]int[)])$' -- "$TMP/simple" \
    >/dev/null 2>"$TMP/ingest.err"
test ! -s "$TMP/ingest.trace"
grep -q 'ingest-sampled out 1 root trace(s)' "$TMP/ingest.err"

"$RUN" --log-rate-limit 1 --histogram --regex \
    --root-scope '^(main|A[(]int[)]|B[(]int[)]|C[(]int[)])$' -- "$TMP/simple" \
    >"$TMP/limited.trace" 2>"$TMP/limited.err"
test "$(grep -Ec '^[0-9]+\.[0-9]{9} ' "$TMP/limited.trace")" -lt 8
grep -q 'suppressed [1-9][0-9]* event line(s) by rate-limit' "$TMP/limited.err"
grep -Eq 'by rate-limit total \(user [1-9][0-9]*, kernel 0\)' "$TMP/limited.err"
grep -q '^Histograms:$' "$TMP/limited.trace"

# File output is not rate-limited, even when the option is present.
"$RUN" --log-rate-limit 1 -o "$TMP/limited-file.trace" --regex \
    --root-scope '^(main|A[(]int[)]|B[(]int[)]|C[(]int[)])$' -- "$TMP/simple" \
    >/dev/null 2>"$TMP/limited-file.err"
! grep -q 'by rate-limit' "$TMP/limited-file.err"
test "$(grep -Ec '^[0-9]+\.[0-9]{9} ' "$TMP/limited-file.trace")" -ge 8

# Kernel lines use a separate bucket and are counted separately.
"$RUN" --kernel --sched --futex --io --log-rate-limit 1 \
    --regex --root-scope '^(main|work[(]int[)]|lock_work[(][)]|fsync_work[(][)])$' \
    -- "$TMP/kernel" > "$TMP/kernel-limited.trace" 2> "$TMP/kernel-limited.err"
grep -q 'suppressed [1-9][0-9]* event line(s) by rate-limit total' \
    "$TMP/kernel-limited.err"
grep -Eq '\(user [0-9]+, kernel [1-9][0-9]*\)' "$TMP/kernel-limited.err"

# A long-running trace reports the throttled delta periodically.
cat > "$TMP/rate_slow.cpp" <<'EOF'
#include <unistd.h>

__attribute__((noinline)) int tick(int x)
{
    return x + 1;
}

int main()
{
    for (int i = 0; i < 80; ++i) {
        tick(i);
        usleep(100000);
    }
    return 0;
}
EOF
g++ -O0 -g -o "$TMP/rate_slow" "$TMP/rate_slow.cpp"
if command -v timeout >/dev/null 2>&1; then
    timeout -s INT 7 "$RUN" --kernel --sched --log-rate-limit 1 --regex \
        --root-scope '^(main|tick[(]int[)])$' -- "$TMP/rate_slow" \
        > "$TMP/rate-slow.trace" 2> "$TMP/rate-slow.err" || true
    grep -q 'event line(s) by rate-limit since last report' "$TMP/rate-slow.err"
    grep -Eq 'by rate-limit since last report \(user [0-9]+, kernel [0-9]+\)' \
        "$TMP/rate-slow.err"
    grep -q 'event line(s) by rate-limit total' "$TMP/rate-slow.err"
else
    echo "timeout not available; skipping periodic rate-limit fixture"
fi

echo "== kernel events: scheduler, futex, I/O =="
"$RUN" --kernel --sched --futex --io \
    -o "$TMP/kernel.trace" --regex \
    --root-scope '^(main|work[(]int[)]|lock_work[(][)]|fsync_work[(][)])$' \
    -- "$TMP/kernel" >/dev/null 2>"$TMP/kernel.err"
grep -q '@SCHED switch_out' "$TMP/kernel.trace"
grep -q '@SCHED switch_in' "$TMP/kernel.trace"
grep -q '@FUTEX wait_begin' "$TMP/kernel.trace"
grep -q '@FUTEX wait_end' "$TMP/kernel.trace"
grep -q '@IO fsync_begin' "$TMP/kernel.trace"
grep -q '@IO fsync_end' "$TMP/kernel.trace"

echo "== kernel events: per-frame histograms =="
"$RUN" --histogram --kernel --sched --futex --io \
    -o "$TMP/kernel-hist.trace" --regex \
    --root-scope '^(main|work[(]int[)]|lock_work[(][)]|fsync_work[(][)])$' \
    -- "$TMP/kernel" >/dev/null 2>"$TMP/kernel-hist.err"
grep -q '^Histograms:$' "$TMP/kernel-hist.trace"
grep -q '^   kernel:$' "$TMP/kernel-hist.trace"
grep -Eq '^     (@futex|@fsync|sched\.(off_cpu|runqueue))$' \
    "$TMP/kernel-hist.trace"
grep -Eq '^       calls=[1-9][0-9]*  total=' "$TMP/kernel-hist.trace"

echo "== kernel events ignore trace depth =="
"$RUN" --trace-depth 0 --kernel --sched --futex --io \
    -o "$TMP/kernel-tdepth.trace" --regex \
    --root-scope '^(main|work[(]int[)]|lock_work[(][)]|fsync_work[(][)])$' \
    -- "$TMP/kernel" >/dev/null 2>"$TMP/kernel-tdepth.err"
grep -q '@SCHED switch_out' "$TMP/kernel-tdepth.trace"
grep -q '@FUTEX wait_begin' "$TMP/kernel-tdepth.trace"
grep -q '@IO fsync_begin' "$TMP/kernel-tdepth.trace"

echo "== kernel events: memory and network =="
"$RUN" --kernel --memory --network \
    -o "$TMP/kernel-mm.trace" --regex \
    --root-scope '^(main|memory_work[(][)]|network_work[(][)])$' \
    -- "$TMP/kernel" >/dev/null 2>"$TMP/kernel-mm.err"
grep -q '@MM page_fault' "$TMP/kernel-mm.trace"
grep -q '@NET socket_begin' "$TMP/kernel-mm.trace"
grep -q '@NET connect_begin' "$TMP/kernel-mm.trace"
grep -q '@NET sendto_begin' "$TMP/kernel-mm.trace"
grep -q '@NET sendto_end' "$TMP/kernel-mm.trace"

echo "== kernel preset scopes =="
preset_include='^(main|fsync_work[(][)]|memory_work[(][)]|network_work[(][)])$'
"$RUN" --kernel --preset latency -o "$TMP/preset-latency.trace" \
    --regex --root-scope "$preset_include" -- "$TMP/kernel" \
    >/dev/null 2>"$TMP/preset-latency.err"
grep -q '@SCHED switch' "$TMP/preset-latency.trace"
grep -q '@NET socket_begin' "$TMP/preset-latency.trace"
! grep -q '@MM' "$TMP/preset-latency.trace"
! grep -q '@NET tcp_retransmit' "$TMP/preset-latency.trace"
! grep -q '@BLOCK' "$TMP/preset-latency.trace"
! grep -q 'block tracepoints are global' "$TMP/preset-latency.err"

"$RUN" --kernel --preset proxy -o "$TMP/preset-net.trace" \
    --regex --root-scope "$preset_include" -- "$TMP/kernel" \
    >/dev/null 2>"$TMP/preset-net.err"
grep -q '@NET socket_begin' "$TMP/preset-net.trace"
! grep -q '@BLOCK' "$TMP/preset-net.trace"
! grep -q 'block tracepoints are global' "$TMP/preset-net.err"

"$RUN" --kernel --preset storage -o "$TMP/preset-storage.trace" \
    --regex --root-scope "$preset_include" -- "$TMP/kernel" \
    >/dev/null 2>"$TMP/preset-storage.err"
grep -q '@IO fsync_begin' "$TMP/preset-storage.trace"
! grep -q '@NET' "$TMP/preset-storage.trace"
! grep -q '@BLOCK' "$TMP/preset-storage.trace"
! grep -q 'block tracepoints are global' "$TMP/preset-storage.err"

"$RUN" --kernel --preset computation \
    -o "$TMP/preset-computation.trace" --regex \
    --root-scope "$preset_include" -- "$TMP/kernel" \
    >/dev/null 2>"$TMP/preset-computation.err"
grep -q '@MM page_fault' "$TMP/preset-computation.trace"
! grep -q '@NET' "$TMP/preset-computation.trace"
! grep -q '@IO' "$TMP/preset-computation.trace"
! grep -q 'block tracepoints are global' "$TMP/preset-computation.err"

"$RUN" --kernel --preset full -o "$TMP/preset-full.trace" \
    --regex --root-scope "$preset_include" -- "$TMP/kernel" \
    >/dev/null 2>"$TMP/preset-full.err"
grep -q '@MM page_fault' "$TMP/preset-full.trace"
grep -q '@NET socket_begin' "$TMP/preset-full.trace"
! grep -q '@BLOCK' "$TMP/preset-full.trace"
! grep -q 'block tracepoints are global' "$TMP/preset-full.err"

"$RUN" --kernel --preset extended -o "$TMP/preset-extended.trace" \
    --regex --root-scope "$preset_include" -- "$TMP/kernel" \
    >/dev/null 2>"$TMP/preset-extended.err"
grep -q '@MM page_fault' "$TMP/preset-extended.trace"
grep -q '@NET socket_begin' "$TMP/preset-extended.trace"
grep -q 'block tracepoints are global' "$TMP/preset-extended.err"

"$RUN" --kernel --block -o "$TMP/preset-block-only.trace" \
    --regex --root-scope "$preset_include" -- "$TMP/kernel" \
    >/dev/null 2>"$TMP/preset-block-only.err"
grep -q 'block tracepoints are global' "$TMP/preset-block-only.err"
! grep -q '@SCHED' "$TMP/preset-block-only.trace"
! grep -q '@IO' "$TMP/preset-block-only.trace"
! grep -q '@NET' "$TMP/preset-block-only.trace"
! grep -q '@MM' "$TMP/preset-block-only.trace"

"$RUN" --kernel --block --io --network \
    -o "$TMP/preset-combined.trace" --regex \
    --root-scope "$preset_include" -- "$TMP/kernel" \
    >/dev/null 2>"$TMP/preset-combined.err"
grep -q 'block tracepoints are global' "$TMP/preset-combined.err"
grep -q '@IO fsync_begin' "$TMP/preset-combined.trace"
grep -q '@NET socket_begin' "$TMP/preset-combined.trace"
! grep -q '@SCHED' "$TMP/preset-combined.trace"
! grep -q '@MM' "$TMP/preset-combined.trace"

echo "== PMU counting =="
"$RUN" --kernel --events pmu -o "$TMP/pmu.trace" --regex \
    --root-scope '^main$' -- "$TMP/pmu" >/dev/null 2>"$TMP/pmu.err"
if grep -q 'PMU unavailable' "$TMP/pmu.err"; then
    echo "PMU unavailable; skipping PMU counting checks"
else
    grep -q '^PMU counters (raw, not scaled):$' "$TMP/pmu.trace"
    grep -Eq '^  tid [0-9][0-9]*' "$TMP/pmu.trace"
    grep -Eq '^    cycles +[0-9]+  enabled=' "$TMP/pmu.trace"
    grep -Eq '^    instructions +[0-9]+  enabled=' "$TMP/pmu.trace"
    grep -q 'PMU 4 counter(s)' "$TMP/pmu.err"
    # PMU-only mode must not load or attach the kernel tracepoint object.
    ! grep -q 'kernel events:' "$TMP/pmu.err"
    ! grep -q 'kernel tracepoints' "$TMP/pmu.err"
fi

echo "== PMU sampling =="
"$RUN" --kernel --pmu cycles --pmu-sampling 10000 --histogram \
    -o "$TMP/pmu-sampling.trace" --regex --root-scope '^main$' \
    -- "$TMP/pmu" >/dev/null 2>"$TMP/pmu-sampling.err"
if grep -q 'PMU unavailable' "$TMP/pmu-sampling.err"; then
    echo "PMU unavailable; skipping PMU sampling checks"
else
    grep -q '@PMU sample event=cycles' "$TMP/pmu-sampling.trace"
    grep -q '^   pmu:$' "$TMP/pmu-sampling.trace"
    grep -Eq '^     cycles  samples=[1-9][0-9]*  events=[1-9][0-9]*' \
        "$TMP/pmu-sampling.trace"
    grep -q 'PMU 1 counter(s)' "$TMP/pmu-sampling.err"
fi

echo "== OTLP native file export =="
"$RUN" -T --exporter otlp-json --export-file "$TMP/live.json" --regex \
    --root-scope '^(main|A[(]int[)]|B[(]int[)]|C[(]int[)])$' -- "$TMP/simple" \
    >/dev/null 2>"$TMP/live.err"
grep -q 'OTLP .* span(s) exported' "$TMP/live.err"
grep -q '"resourceSpans"' "$TMP/live.json"
grep -q '"name":"main"' "$TMP/live.json"
grep -q '"name":"C(int)"' "$TMP/live.json"
if command -v python3 >/dev/null 2>&1; then
    python3 - "$TMP/live.json" <<'PY'
import json, sys
doc = json.load(open(sys.argv[1]))
spans = doc["resourceSpans"][0]["scopeSpans"][0]["spans"]
by_name = {s["name"]: s for s in spans}
assert "main" in by_name and "C(int)" in by_name and "B(int)" in by_name
assert by_name["main"].get("parentSpanId") is None
assert by_name["C(int)"]["parentSpanId"] == by_name["main"]["spanId"]
attributes = {a["key"]: a["value"] for a in by_name["main"]["attributes"]}
assert attributes["callgraph.depth"]["intValue"] == "0"
assert attributes["code.function.name"]["stringValue"] == "main"
assert attributes["code.function"]["stringValue"] == "main"
assert attributes["code.filepath"]["stringValue"].endswith("simple.cpp")
assert int(attributes["code.lineno"]["intValue"]) > 0
assert attributes["callgraph.module"]["stringValue"] == "simple"
PY
fi

"$RUN" -T --exporter otlp-json --export-file "$TMP/live-complete.json" \
    --complete-traces --outlier-latency-quantile 0.99 --regex \
    --root-scope '^(main|A[(]int[)]|B[(]int[)]|C[(]int[)])$' -- "$TMP/simple" \
    >/dev/null 2>"$TMP/live-complete.err"
grep -q 'trace buffer: 1 completed' "$TMP/live-complete.err"
grep -q 'callgraph.quantile' "$TMP/live-complete.json"

echo "== OTLP kernel spans =="
"$RUN" -T --kernel --io --sched --memory \
    --exporter otlp-json --export-file "$TMP/kernel-spans.json" --regex \
    --root-scope '^(main|fsync_work[(][)]|memory_work[(][)]|lock_work[(][)]|work[(]int[)]|network_work[(][)])$' \
    -- "$TMP/kernel" >/dev/null 2>"$TMP/kernel-spans.err"
grep -q 'kernel spans:' "$TMP/kernel-spans.err"
grep -q '"key":"callgraph.kernel.event"' "$TMP/kernel-spans.json"
grep -q '"key":"callgraph.kernel.category"' "$TMP/kernel-spans.json"
if command -v python3 >/dev/null 2>&1; then
    python3 - "$TMP/kernel-spans.json" <<'PY'
import json, sys
doc = json.load(open(sys.argv[1]))
spans = doc["resourceSpans"][0]["scopeSpans"][0]["spans"]
by_id = {s["spanId"]: s for s in spans}
kernel = [s for s in spans
          if any(a["key"] == "callgraph.kernel.event" for a in s["attributes"])]
assert kernel, "no kernel spans exported"
names = {s["name"] for s in kernel}
assert "@fsync" in names or "@openat" in names, names
assert "sched.off_cpu" in names, names
assert any(name.startswith("page_fault.") for name in names), names
for span in kernel:
    attrs = {a["key"]: a["value"] for a in span["attributes"]}
    assert "callgraph.kernel.category" in attrs
    assert "thread.id" in attrs
    assert "callgraph.depth" in attrs
    assert "code.function.name" not in attrs
    assert span.get("parentSpanId") in by_id
PY
fi

echo "== OTLP/HTTP protobuf export =="
if command -v python3 >/dev/null 2>&1 && "$RUN" --version | grep -q 'otlp protobuf: yes'; then
    python3 - "$RUN" "$TMP/simple" <<'PY'
import http.server, subprocess, sys, threading, time

binary, target = sys.argv[1:3]
requests = []
class Handler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        n = int(self.headers.get("Content-Length", "0"))
        requests.append({
            "path": self.path,
            "type": self.headers.get("Content-Type"),
            "body": self.rfile.read(n),
        })
        self.send_response(200)
        self.send_header("Content-Type", "application/x-protobuf")
        self.end_headers()
        self.wfile.write(b"")
    def log_message(self, *args):
        pass

server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
thread = threading.Thread(target=server.serve_forever, daemon=True)
thread.start()
port = server.server_port
result = subprocess.run(
    [binary, "-T",
     "--exporter", "otlp-http",
     "--endpoint", f"http://127.0.0.1:{port}",
     "--regex", "--root-scope", "^(main|C[(]int[)])$", "--", target],
    capture_output=True, text=True, timeout=60)
server.shutdown()
thread.join(timeout=5)
server.server_close()
assert result.returncode == 0, result.stderr
assert requests, "mock OTLP/HTTP server received no request"
assert all(r["path"] == "/v1/traces" for r in requests), requests
assert all(r["type"] == "application/x-protobuf" for r in requests), requests
assert all(r["body"] for r in requests), requests
assert "OTLP" in result.stderr, result.stderr
PY
fi

echo "== OTLP attach mode =="
cat > "$TMP/attach_target.cpp" <<'EOF'
#include <unistd.h>
__attribute__((noinline)) int leaf(int x) { usleep(2000); return x + 1; }
__attribute__((noinline)) int worker(int x) { return leaf(x) + leaf(x + 1); }
int main() {
    sleep(2);
    for (int i = 0; i < 100; ++i) worker(i);
    sleep(2);
    return 0;
}
EOF
g++ -O0 -g -o "$TMP/attach_target" "$TMP/attach_target.cpp"
"$TMP/attach_target" &
attach_pid=$!
sleep 0.2
"$ATTACH" -p "$attach_pid" \
    --exporter otlp-json --export-file "$TMP/attach.json" \
    --service-name attach-test --regex \
    --root-scope '^(worker[(]int[)]|leaf[(]int[)])$' \
    >/dev/null 2>"$TMP/attach.err"
wait "$attach_pid" || true
grep -q 'OTLP .* span(s) exported' "$TMP/attach.err"
grep -q '"key":"callgraph.attach_mode","value":{"boolValue":true}' "$TMP/attach.json"
grep -q '"key":"callgraph.partial_stack","value":{"boolValue":true}' "$TMP/attach.json"
grep -q '"name":"worker(int)"' "$TMP/attach.json"

echo "== OTLP complete traces =="
if command -v python3 >/dev/null 2>&1 &&
   "$RUN" --version | grep -q 'otlp protobuf: yes' &&
   "$RUN" --version | grep -q 'otlp http: yes'; then
    cat > "$TMP/complete_target.cpp" <<'EOF'
#include <unistd.h>
__attribute__((noinline)) int child(int x) { return x + 1; }
__attribute__((noinline)) int worker(int x) {
    int y = child(x);
    usleep(2000000);
    return y;
}
int main() { sleep(2); return worker(1); }
EOF
    g++ -O0 -g -o "$TMP/complete_target" "$TMP/complete_target.cpp"
    python3 - "$ATTACH" "$TMP/complete_target" <<'PY'
import http.server, subprocess, sys, threading, time

binary, target = sys.argv[1:3]
requests = []

class Handler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        n = int(self.headers.get("Content-Length", "0"))
        requests.append((time.time(), self.rfile.read(n)))
        self.send_response(200)
        self.send_header("Content-Type", "application/x-protobuf")
        self.end_headers()
        self.wfile.write(b"")
    def log_message(self, *args):
        pass

server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
thread = threading.Thread(target=server.serve_forever, daemon=True)
thread.start()
proc = subprocess.Popen([target])
try:
    time.sleep(0.2)
    started = time.time()
    result = subprocess.run(
        [binary, "-p", str(proc.pid), "--complete-traces",
         "--exporter", "otlp-http",
         "--endpoint", f"http://127.0.0.1:{server.server_port}",
         "--regex", "--root-scope", "^(main|worker[(]int[)]|child[(]int[)])$"],
        capture_output=True, text=True, timeout=30)
    proc.wait(timeout=10)
finally:
    server.shutdown()
    thread.join(timeout=5)
    server.server_close()
    if proc.poll() is None:
        proc.kill()

assert result.returncode == 0, result.stderr
assert requests, result.stderr
assert "trace buffer: 1 completed" in result.stderr, result.stderr
first = requests[0][0] - started
assert first > 3.0, (first, result.stderr)
body = b"".join(request[1] for request in requests)
assert b"worker(int)" in body, result.stderr
assert b"child(int)" in body, result.stderr
PY
fi

echo "== attach kernel block defaults =="
cat > "$TMP/attach_kernel_target.cpp" <<'EOF'
#include <unistd.h>
__attribute__((noinline)) int leaf(int x) { usleep(2000); return x + 1; }
__attribute__((noinline)) int worker(int x) { return leaf(x) + leaf(x + 1); }
int main() {
    sleep(1);
    for (int i = 0; i < 50; ++i) worker(i);
    sleep(1);
    return 0;
}
EOF
g++ -O0 -g -o "$TMP/attach_kernel_target" "$TMP/attach_kernel_target.cpp"
"$TMP/attach_kernel_target" &
attach_pid=$!
sleep 0.2
"$ATTACH" -p "$attach_pid" --kernel -o "$TMP/attach-default.trace" \
    --regex --root-scope '^(worker[(]int[)]|leaf[(]int[)])$' \
    >/dev/null 2>"$TMP/attach-default.err"
wait "$attach_pid" || true
grep -q 'kernel events:' "$TMP/attach-default.err"
! grep -q 'block tracepoints are global' "$TMP/attach-default.err"

"$TMP/attach_kernel_target" &
attach_pid=$!
sleep 0.2
"$ATTACH" -p "$attach_pid" --kernel --preset storage --block \
    -o "$TMP/attach-storage.trace" --regex \
    --root-scope '^(worker[(]int[)]|leaf[(]int[)])$' \
    >/dev/null 2>"$TMP/attach-storage.err"
wait "$attach_pid" || true
grep -q 'block tracepoints are global' "$TMP/attach-storage.err"

"$TMP/attach_kernel_target" &
attach_pid=$!
sleep 0.2
"$ATTACH" -p "$attach_pid" --kernel --block \
    -o "$TMP/attach-block-only.trace" --regex \
    --root-scope '^(worker[(]int[)]|leaf[(]int[)])$' \
    >/dev/null 2>"$TMP/attach-block-only.err"
wait "$attach_pid" || true
grep -q 'block tracepoints are global' "$TMP/attach-block-only.err"
! grep -q '@SCHED' "$TMP/attach-block-only.trace"
! grep -q '@IO' "$TMP/attach-block-only.trace"
! grep -q '@NET' "$TMP/attach-block-only.trace"
! grep -q '@MM' "$TMP/attach-block-only.trace"

echo "== wall-clock timestamps =="
"$RUN" -T -o "$TMP/wall.trace" --regex \
    --root-scope '^(main|C[(]int[)])$' -- "$TMP/simple" >/dev/null 2>/dev/null
grep -Eq '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{9}[+-][0-9]{2}:[0-9]{2} [0-9]+ : 0 -> main' "$TMP/wall.trace"

echo "== indentation =="
"$RUN" --indent 2 -o "$TMP/indent.trace" --regex \
    --root-scope '^(main|A[(]int[)]|B[(]int[)]|C[(]int[)])$' -- "$TMP/simple" \
    >/dev/null 2>/dev/null
grep -Eq ' : 0 -> main$' "$TMP/indent.trace"
grep -Eq ' : 1 -> {3}C[(]int[)]$' "$TMP/indent.trace"
grep -Eq ' : 2 -> {5}B[(]int[)]$' "$TMP/indent.trace"
grep -Eq ' : 3 -> {7}A[(]int[)]$' "$TMP/indent.trace"
grep -Eq ' : 3 <- {7}A[(]int[)]$' "$TMP/indent.trace"

if [ "$(uname -m)" = "x86_64" ]; then
    echo "== function arguments =="
    cat > "$TMP/args.cpp" <<'EOF'
#include <cstdio>

__attribute__((noinline)) int many(int a, int b, int c, int d, int e, int f,
                                   int g)
{
    return a + b + c + d + e + f + g;
}

__attribute__((noinline)) int ptr(const char* s, bool flag, char ch)
{
    return (s != nullptr) + flag + ch;
}

int main()
{
    std::printf("%d %d\n", many(1, 2, 3, 4, 5, 6, 7),
                ptr("hi", true, 'A'));
    return 0;
}
EOF
    g++ -O0 -g -o "$TMP/args" "$TMP/args.cpp"
    "$RUN" --show-args -o "$TMP/args.trace" --regex \
        --root-scope '^(main|many[(]int, int, int, int, int, int, int[)]|ptr[(]char const[*], bool, char[)])$' \
        -- "$TMP/args" >/dev/null 2>/dev/null
    grep -q ' : 1 -> many(int, int, int, int, int, int, int) (a=1, b=2, c=3, d=4, e=5, f=6, g=7)' "$TMP/args.trace"
    grep -Eq " : 1 -> ptr[(]char const[*], bool, char[)] [(]s=0x[0-9a-f]+, flag=true, ch='A'[)]" "$TMP/args.trace"
    grep -q ' : 1 <- many(int, int, int, int, int, int, int)$' "$TMP/args.trace"

    echo "== function arguments with external debug info =="
    "$RUN" --show-args -o "$TMP/detached-args.trace" --regex \
        --root-scope '^(main|A[(]int[)])$' -- "$TMP/detached" \
        >/dev/null 2>/dev/null
    grep -q 'A(int) (x=3)' "$TMP/detached-args.trace"
else
    echo "== function arguments skipped (not x86-64) =="
fi

echo "== trace recursive =="
"$RUN" -o "$TMP/rec.trace" --regex \
    --root-scope '^(main|factorial[(]int[)])$' -- "$TMP/recursive" \
    >/dev/null 2>/dev/null
grep -q ' : 1 -> factorial(int)' "$TMP/rec.trace"
grep -q ' : 2 -> factorial(int)' "$TMP/rec.trace"
grep -q ' : 3 -> factorial(int)' "$TMP/rec.trace"
grep -q ' : 3 <- factorial(int)' "$TMP/rec.trace"

echo "== trace multithreaded =="
"$RUN" -o "$TMP/mt.trace" --regex \
    --root-scope '^(main|worker[(]int[)]|leaf[(]int[)])$' -- "$TMP/multithread" \
    >/dev/null 2>/dev/null
grep -q 'worker(int)' "$TMP/mt.trace"
grep -q 'leaf(int)' "$TMP/mt.trace"
awk '{print $2}' "$TMP/mt.trace" | sort -u | wc -l | grep -qx '3'

echo "== max depth =="
"$RUN" -o "$TMP/depth.trace" --max-depth 1 --regex \
    --root-scope '^(main|A[(]int[)]|B[(]int[)]|C[(]int[)])$' -- "$TMP/simple" \
    >/dev/null 2>/dev/null
! grep -q ' : 2 ' "$TMP/depth.trace"
grep -q ' : 1 -> C(int)' "$TMP/depth.trace"

echo "== trace depth =="
# The default is unlimited.
"$RUN" -o "$TMP/tdepth-default.trace" --regex \
    --root-scope '^(main|A[(]int[)]|B[(]int[)]|C[(]int[)])$' -- "$TMP/simple" \
    >/dev/null 2>/dev/null
grep -q ' : 2 ' "$TMP/tdepth-default.trace"

# 0 is explicit root-only.
"$RUN" --trace-depth 0 --static-graph "$TMP/simple.json" \
    -o "$TMP/tdepth-0.trace" --regex \
    --root-scope '^(main|A[(]int[)]|B[(]int[)]|C[(]int[)])$' -- "$TMP/simple" \
    >/dev/null 2>/dev/null
! grep -q ' : 1 ' "$TMP/tdepth-0.trace"

# 1 keeps the root and one level.
"$RUN" --trace-depth 1 --static-graph "$TMP/simple.json" \
    -o "$TMP/tdepth-1.trace" --regex \
    --root-scope '^(main|A[(]int[)]|B[(]int[)]|C[(]int[)])$' -- "$TMP/simple" \
    >/dev/null 2>/dev/null
grep -q ' : 1 -> C(int)' "$TMP/tdepth-1.trace"
! grep -q ' : 2 ' "$TMP/tdepth-1.trace"

# Without --root-scope the same rule counts from global depth 0.
"$RUN" --trace-depth 1 --static-graph "$TMP/simple.json" \
    -o "$TMP/tdepth-global.trace" --regex \
    -- "$TMP/simple" >/dev/null 2>/dev/null
! grep -Eq ' : ([2-9]|[1-9][0-9]+) ' "$TMP/tdepth-global.trace"

# An excluded node is skipped and its descendants splice up: B is absent,
# and A appears at depth 2 under C.
"$RUN" --trace-depth 2 --static-graph "$TMP/simple.json" \
    -o "$TMP/tdepth-exclude.trace" --regex \
    --root-scope '^(main|A[(]int[)]|B[(]int[)]|C[(]int[)])$' \
    --exclude '^B[(]int[)]$' -- "$TMP/simple" >/dev/null 2>/dev/null
! grep -q 'B(int)' "$TMP/tdepth-exclude.trace"
grep -q ' : 2 -> A(int)' "$TMP/tdepth-exclude.trace"

# Deeper user frames are absent from the histogram too.
"$RUN" --trace-depth 1 --static-graph "$TMP/simple.json" \
    --histogram -o "$TMP/tdepth-hist.trace" --regex \
    --root-scope '^(main|A[(]int[)]|B[(]int[)]|C[(]int[)])$' -- "$TMP/simple" \
    >/dev/null 2>/dev/null
! grep -q '^2\. ' "$TMP/tdepth-hist.trace"

if "$RUN" --trace-depth -1 --dry-run -- "$TMP/simple" >/dev/null 2>&1; then
    echo "expected negative --trace-depth to fail" >&2
    exit 1
fi

echo "== root scope and static pruning =="
# --root-scope selects roots; descendants outside the pattern are traced.
"$RUN" -o "$TMP/rootdesc.trace" --regex --root-scope '^main$' \
    -- "$TMP/simple" >/dev/null 2>/dev/null
grep -q ' : 0 -> main' "$TMP/rootdesc.trace"
grep -q ' : 1 -> C(int)' "$TMP/rootdesc.trace"
grep -q ' : 2 -> B(int)' "$TMP/rootdesc.trace"
grep -q ' : 3 -> A(int)' "$TMP/rootdesc.trace"

# N=1 prunes depth-2 descendants and reports the pruning decision.
"$RUN" --trace-depth 1 --static-graph "$TMP/simple.json" \
    -o "$TMP/rootprune1.trace" --regex \
    --root-scope '^main$' -- "$TMP/simple" >/dev/null 2>"$TMP/rootprune1.err"
grep -q ' : 1 -> C(int)' "$TMP/rootprune1.trace"
! grep -q ' : 2 ' "$TMP/rootprune1.trace"
grep -q 'static prune: kept' "$TMP/rootprune1.err"

# Dry-run applies the same pruning.
dry=$("$RUN" --trace-depth 1 --static-graph "$TMP/simple.json" \
    --dry-run --regex --root-scope '^main$' -- "$TMP/simple" 2>/dev/null)
! echo "$dry" | grep -q 'B(int)'
! echo "$dry" | grep -q 'A(int)'

# N=2 keeps the depth-2 functions but still hides depth 3 at runtime.
"$RUN" --trace-depth 2 --static-graph "$TMP/simple.json" \
    -o "$TMP/rootprune2.trace" --regex \
    --root-scope '^main$' -- "$TMP/simple" >/dev/null 2>/dev/null
grep -q ' : 2 -> B(int)' "$TMP/rootprune2.trace"
grep -q ' : 2 -> A(int)' "$TMP/rootprune2.trace"
! grep -q ' : 3 ' "$TMP/rootprune2.trace"

echo "== direct-call pruning default =="
cat > "$TMP/indirect.cpp" <<'EOF'
using Fn = int (*)(int);

__attribute__((noinline)) int indirect_callee(int x) { return x + 1; }
__attribute__((noinline)) int direct_callee(int x) { return x + 2; }

__attribute__((noinline)) int root(Fn fn, int x)
{
    return fn(x) + direct_callee(x);
}

int main()
{
    return root(indirect_callee, 1);
}
EOF
g++ -O0 -g -o "$TMP/indirect" "$TMP/indirect.cpp"
"$DISASM" "$TMP/indirect" -o "$TMP/indirect.json"
"$RUN" --trace-depth 1 --static-graph "$TMP/indirect.json" --dry-run \
    --root-scope 'root*' \
    -- "$TMP/indirect" > "$TMP/indirect.direct" 2>/dev/null
grep -q 'direct_callee(int)' "$TMP/indirect.direct"
! grep -q 'indirect_callee(int)' "$TMP/indirect.direct"
# Omitting --trace-depth disables pruning, so the indirect callee is included.
"$RUN" --dry-run --root-scope 'root*' -- "$TMP/indirect" \
    > "$TMP/indirect.unlimited" 2>/dev/null
grep -q 'indirect_callee(int)' "$TMP/indirect.unlimited"

echo "== conditional-jump targets are not probes =="
if [ "$(uname -m)" = "x86_64" ] && command -v as >/dev/null 2>&1 && \
   command -v ld >/dev/null 2>&1; then
    cat > "$TMP/jcc.s" <<'EOF'
.text
.globl _start
.type _start,@function
_start:
    lea dummy(%rip), %rsi
    xor %edi, %edi
    call hot
    mov $60, %eax
    xor %edi, %edi
    syscall
.size _start,.-_start

.type hot,@function
hot:
    test %edi, %edi
    jne cold
    call *%rsi
    ret
.size hot,.-hot

.type cold,@function
cold:
    ret
.size cold,.-cold

.type dummy,@function
dummy:
    ret
.size dummy,.-dummy
EOF
    as -o "$TMP/jcc.o" "$TMP/jcc.s"
    ld -static -o "$TMP/jcc" "$TMP/jcc.o"
    "$DISASM" "$TMP/jcc" -o "$TMP/jcc.json"
    "$RUN" --trace-depth 1 --static-graph "$TMP/jcc.json" --dry-run \
        -- "$TMP/jcc" > "$TMP/jcc.direct" 2>"$TMP/jcc.err"
    if grep -q 'static prune: kept' "$TMP/jcc.err"; then
        ! grep -q 'cold' "$TMP/jcc.direct"
        grep -q 'hot' "$TMP/jcc.direct"
    else
        echo "static analysis unavailable; skipping jcc fixture"
    fi
else
    echo "as/ld not available; skipping jcc fixture"
fi

echo "== attach without root-scope =="
cat > "$TMP/attach_slow.cpp" <<'EOF'
#include <unistd.h>
int main() { usleep(500000); return 0; }
EOF
g++ -O0 -g -o "$TMP/attach_slow" "$TMP/attach_slow.cpp"
"$TMP/attach_slow" &
attach_pid=$!
sleep 0.1
"$ATTACH" --dry-run -p "$attach_pid" --trace-depth 1 --regex \
    >/dev/null 2>"$TMP/attach-none.err" || true
wait "$attach_pid" || true
grep -q 'static call-graph analysis unavailable' "$TMP/attach-none.err"
grep -q 'Instrumenting 0 functions' "$TMP/attach-none.err"

echo "== latency histogram =="
"$RUN" --histogram -o "$TMP/hist.trace" --regex \
    --root-scope '^(main|A[(]int[)]|B[(]int[)]|C[(]int[)])$' -- "$TMP/simple" \
    >/dev/null 2>/dev/null
grep -q '^=== thread [0-9][0-9]* ===$' "$TMP/hist.trace"
grep -q '^Tree:$' "$TMP/hist.trace"
grep -q '^Histograms:$' "$TMP/hist.trace"
grep -Fqx '0. main' "$TMP/hist.trace"
grep -Fqx '1. C(int)' "$TMP/hist.trace"
grep -Eq '^└── C\(int\).* [0-9.]+(ns|us|ms|s)$' "$TMP/hist.trace"
grep -Eq '^main.* [0-9.]+(ns|us|ms|s)$' "$TMP/hist.trace"
grep -q '├── ' "$TMP/hist.trace"
grep -q '^   calls=1  total=' "$TMP/hist.trace"
# One bar per function entry, under its heading, measuring the function's share
# of the root span; bucket lines carry only the label and count.
grep -Eq '^   -+$' "$TMP/hist.trace"
grep -A1 '^0\. main$' "$TMP/hist.trace" | grep -Eq '^   -+$'
grep -Eq '^   \[ .*\)  [0-9]+$' "$TMP/hist.trace"
grep -q ' : 0 -> main' "$TMP/hist.trace"
tree_line=$(grep -n '^Tree:$' "$TMP/hist.trace" | head -1 | cut -d: -f1)
hist_line=$(grep -n '^Histograms:$' "$TMP/hist.trace" | head -1 | cut -d: -f1)
[ "$tree_line" -lt "$hist_line" ]
# Without the option the report is absent.
! grep -q '^=== thread ' "$TMP/simple.trace"

echo "== latency histogram: one pair per root =="
"$RUN" --histogram -o "$TMP/hist_mt.trace" --regex \
    --root-scope '^(main|worker[(]int[)]|leaf[(]int[)])$' -- "$TMP/multithread" \
    >/dev/null 2>/dev/null
sections=$(grep -c '^=== thread ' "$TMP/hist_mt.trace" || true)
[ "$sections" -ge 2 ]

echo "== latency histogram: tree and histograms paired per root =="
"$RUN" --histogram -o "$TMP/hist_roots.trace" --regex \
    --root-scope '^(task_a[(]int[)]|task_b[(]int[)]|leaf[(]int[)])$' -- "$TMP/tworoots" \
    >/dev/null 2>/dev/null
[ "$(grep -c '^Tree:$' "$TMP/hist_roots.trace")" -eq 2 ]
[ "$(grep -c '^Histograms:$' "$TMP/hist_roots.trace")" -eq 2 ]
[ "$(grep -E '^(Tree|Histograms):$' "$TMP/hist_roots.trace" | tr '\n' ' ')" = \
  "Tree: Histograms: Tree: Histograms: " ]
# Each root keeps its own leaf entry: four single-call blocks, not a merged
# two-call leaf in one thread-wide histogram section.
[ "$(grep -c '^   calls=1 ' "$TMP/hist_roots.trace")" -eq 4 ]

echo "== exception-safe return mode =="
if "$DISASM" "$TMP/exceptions" -o "$TMP/exceptions.json" 2>/dev/null; then
    "$RUN" --return-mode ret --static-graph "$TMP/exceptions.json" \
        -o "$TMP/exc.trace" --regex \
        --root-scope '^(main|outer[(][)]|middle[(][)]|inner[(][)])$' -- "$TMP/exceptions" \
        >/dev/null 2>"$TMP/exc.err"
    grep -q ' : 3 -> inner()' "$TMP/exc.trace"
    grep -q ' : 1 <- outer()' "$TMP/exc.trace"
    grep -q ' : 0 <- main' "$TMP/exc.trace"
    grep -Eq '[1-9][0-9]* desync' "$TMP/exc.err"
else
    echo "libopcodes not available; skipping ret mode"
fi

echo "== longjmp resynchronisation =="
"$RUN" -o "$TMP/lj.trace" --regex \
    --root-scope '^(main|error_path[(][)]|deep[(]int[)])$' -- "$TMP/longjmp" \
    >/dev/null 2>"$TMP/lj.err"
grep -q ' : 0 -> main' "$TMP/lj.trace"
# Each attempt must start error_path() at depth 1.  Without rsp-based
# unwinding, the frames abandoned by the previous longjmp would push it
# deeper on every iteration.
[ "$(grep -c ' : 1 -> error_path()' "$TMP/lj.trace")" -eq 3 ]
awk '$5 == "->" && $6 == "error_path()" && $4 != 1 { bad = 1 }
     END { exit bad }' "$TMP/lj.trace"
grep -Eq '[1-9][0-9]* desync' "$TMP/lj.err"

# --no-rsp-resync disables that repair: the abandoned frames accumulate, so
# the error path starts deeper on every iteration.
"$RUN" --no-rsp-resync -o "$TMP/lj_norsp.trace" --regex \
    --root-scope '^(main|error_path[(][)]|deep[(]int[)])$' -- "$TMP/longjmp" \
    >/dev/null 2>"$TMP/lj_norsp.err"
awk '$5 == "->" && $6 == "error_path()" {
         if (n++ && $4 <= prev) bad = 1
         prev = $4
     }
     END { exit (n == 3 && !bad) ? 0 : 1 }' "$TMP/lj_norsp.trace"

echo "== stackful coroutine (ucontext) =="
"$RUN" -o "$TMP/uctx.trace" --regex \
    --root-scope '^(main|fiber_body[(][)]|leaf[(][)])$' -- "$TMP/ucontext" \
    >/dev/null 2>"$TMP/uctx.err"
# The fiber runs on a separate stack.  Switching back to the main stack looks
# like an unwind, so the suspended fiber_body frame is dropped and the main
# stack call is attributed to main.
grep -Eq '[1-9][0-9]* desync' "$TMP/uctx.err"
[ "$(grep -c ' : 2 -> leaf()' "$TMP/uctx.trace")" -eq 1 ]

# --no-rsp-resync keeps the suspended frame, so every leaf nests under
# fiber_body.
"$RUN" --no-rsp-resync -o "$TMP/uctx_norsp.trace" --regex \
    --root-scope '^(main|fiber_body[(][)]|leaf[(][)])$' -- "$TMP/ucontext" \
    >/dev/null 2>"$TMP/uctx_norsp.err"
[ "$(grep -c ' : 2 -> leaf()' "$TMP/uctx_norsp.trace")" -eq 3 ]

# uretprobes lose the fiber's return across the switch, so ret mode is needed
# for complete pairing.  Together with --no-rsp-resync nothing is desynced.
if "$DISASM" "$TMP/ucontext" -o "$TMP/ucontext.json" 2>/dev/null; then
    "$RUN" --return-mode ret --static-graph "$TMP/ucontext.json" \
        --no-rsp-resync -o "$TMP/uctx_ret.trace" \
        --regex --root-scope '^(main|fiber_body[(][)]|leaf[(][)])$' \
        -- "$TMP/ucontext" >/dev/null 2>"$TMP/uctx_ret.err"
    grep -q '0 desync' "$TMP/uctx_ret.err"
    grep -q '0 stray' "$TMP/uctx_ret.err"
    grep -q ' : 1 <- fiber_body()' "$TMP/uctx_ret.trace"
fi

echo "== shared library discovered after load =="
cat > "$TMP/lib.cpp" <<'EOF'
int foo(int x) { return x + 1; }
EOF
cat > "$TMP/use_lib.cpp" <<'EOF'
#include <unistd.h>
int foo(int);
int main() {
    usleep(400000);
    for (int i = 0; i < 2; ++i)
        foo(i);
    return 0;
}
EOF
g++ -O0 -g -shared -fPIC -o "$TMP/libfoo.so" "$TMP/lib.cpp"
g++ -O0 -g -o "$TMP/use_lib" "$TMP/use_lib.cpp" -L"$TMP" -lfoo -Wl,-rpath,"$TMP"
"$RUN" --module 'libfoo.so' -o "$TMP/lib.trace" --regex --root-scope '^foo' \
    -- "$TMP/use_lib" >/dev/null 2>/dev/null
grep -q 'foo(int)' "$TMP/lib.trace"
grep -q ' <- foo(int)' "$TMP/lib.trace"

echo "all integration tests passed"
