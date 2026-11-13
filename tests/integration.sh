#!/usr/bin/env bash
set -euo pipefail

BIN=${1:?usage: integration.sh /path/to/callgraph}
ROOT=$(cd "$(dirname "$0")/.." && pwd)
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

g++ -O0 -g -o "$TMP/simple" "$ROOT/examples/simple.cpp"
g++ -O0 -g -o "$TMP/recursive" "$ROOT/examples/recursive.cpp"
g++ -O0 -g -pthread -o "$TMP/multithread" "$ROOT/examples/multithread.cpp"
g++ -O0 -g -pthread -o "$TMP/tworoots" "$ROOT/examples/tworoots.cpp"
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
dry=$("$BIN" run --dry-run --regex \
    --include '^(main|A[(]int[)]|B[(]int[)]|C[(]int[)])$' -- "$TMP/simple" 2>/dev/null)
echo "$dry" | grep -q 'main'
echo "$dry" | grep -q 'A(int)'
echo "$dry" | grep -q 'B(int)'

echo "== dry run: glob + exclude =="
dry=$("$BIN" run --dry-run --include '*' --exclude 'A*' -- "$TMP/simple" 2>/dev/null)
! echo "$dry" | grep -q 'A(int)'

echo "== dry run: stripped binary fails =="
cp "$TMP/simple" "$TMP/stripped"
strip "$TMP/stripped"
if "$BIN" run --dry-run -- "$TMP/stripped" >/dev/null 2>&1; then
    echo "expected a stripped binary to fail" >&2
    exit 1
fi

echo "== dry run: stripped binary with separate debug info =="
cp "$TMP/simple" "$TMP/detached"
objcopy --only-keep-debug "$TMP/detached" "$TMP/detached.debug"
strip --strip-all "$TMP/detached"
objcopy --add-gnu-debuglink="$TMP/detached.debug" "$TMP/detached"
dry=$("$BIN" run --dry-run --regex --include '^(main|A[(]int[)])$' \
    -- "$TMP/detached" 2>/dev/null)
echo "$dry" | grep -q 'main'
echo "$dry" | grep -q 'A(int)'

echo "== OTLP offline conversion =="
cat > "$TMP/otel.trace" <<'EOF'
2026-11-12T10:00:00.000000000+00:00 100 : 0 -> main
2026-11-12T10:00:00.000001000+00:00 100 : 1 -> C(int)
2026-11-12T10:00:00.000002000+00:00 100 : 2 -> B(int)
2026-11-12T10:00:00.000003000+00:00 100 : 2 <- B(int)
2026-11-12T10:00:00.000004000+00:00 100 : 1 <- C(int)
2026-11-12T10:00:00.000005000+00:00 100 : 0 <- main
EOF
"$BIN" export --otel --input "$TMP/otel.trace" --output "$TMP/otel.json" \
    --service-name demo --trace-id-seed 1234 2>"$TMP/otel.err"
grep -q 'converted 6 events' "$TMP/otel.err"
grep -q '3 OTLP span(s)' "$TMP/otel.err"
grep -q '"resourceSpans"' "$TMP/otel.json"
grep -q '"service.name","value":{"stringValue":"demo"}' "$TMP/otel.json"
grep -q '"name":"C(int)"' "$TMP/otel.json"
"$BIN" export --otel --input "$TMP/otel.trace" --output "$TMP/sampled.json" \
    --sample-rate 0 2>/dev/null
if command -v python3 >/dev/null 2>&1; then
    python3 - "$TMP/sampled.json" <<'PY'
import json, sys
doc = json.load(open(sys.argv[1]))
assert len(doc["resourceSpans"][0]["scopeSpans"][0]["spans"]) == 0
PY
fi

echo "== OTLP offline boot-second anchor =="
cat > "$TMP/boot.trace" <<'EOF'
100.000000000 7 : 0 -> main
100.000001000 7 : 1 -> C(int)
100.000002000 7 : 1 <- C(int)
100.000003000 7 : 0 <- main
EOF
"$BIN" export --otel --input "$TMP/boot.trace" --output "$TMP/boot.json" \
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
"$BIN" export --flame --input "$TMP/boot.trace" \
    --output "$TMP/boot.folded" 2>"$TMP/flame.err"
grep -q 'converted .* events into .* folds' "$TMP/flame.err"
grep -qx 'main 1' "$TMP/boot.folded"
grep -qx 'main;C(int) 1' "$TMP/boot.folded"
cat > "$TMP/flame-incomplete.trace" <<'EOF'
100.000000000 7 : 0 -> main
100.000001000 7 : 1 -> A(int)
100.000002000 7 : 0 <- main
EOF
"$BIN" export --flame --input "$TMP/flame-incomplete.trace" \
    --output "$TMP/flame-incomplete.folded" 2>/dev/null
grep -Fqx 'main;A(int);[incomplete] 1' "$TMP/flame-incomplete.folded"
grep -qx 'main 1' "$TMP/flame-incomplete.folded"
"$BIN" export --flame --help | grep -q 'flamegraph.pl'
if "$BIN" export --flame --metadata "$TMP/otel.meta" \
    --input "$TMP/boot.trace" >/dev/null 2>&1; then
    echo "expected OTel options to be rejected with --flame" >&2
    exit 1
fi
if "$BIN" export otel --input "$TMP/boot.trace" >/dev/null 2>&1; then
    echo "expected the old 'export otel' form to be rejected" >&2
    exit 1
fi

if command -v python3 >/dev/null 2>&1; then
    echo "== OTLP JSON validation and HTTP + gzip export =="
    python3 - "$BIN" "$TMP/otel.json" "$TMP/otel.trace" <<'PY'
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
    [binary, "export", "--otel", "--input", trace_path,
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
    "$BIN" run --dry-run --regex --include '^main\.main$' -- "$GO_BIN" \
        >/dev/null 2>"$TMP/gowarn.err"
    grep -q 'Go binary' "$TMP/gowarn.err"
    grep -q -- '--return-mode=ret' "$TMP/gowarn.err"

    "$BIN" run --dry-run --return-mode ret --regex \
        --include '^main\.main$' -- "$GO_BIN" \
        >/dev/null 2>"$TMP/gowarn_ret.err"
    grep -q 'nesting unreliable' "$TMP/gowarn_ret.err"

    if (cd "$TMP" && go build -ldflags="-s -w" -o "$TMP/gowarn_stripped" \
            gowarn.go) >/dev/null 2>&1; then
        if "$BIN" run --dry-run -- "$TMP/gowarn_stripped" \
                >/dev/null 2>"$TMP/gowarn_stripped.err"; then
            echo "expected a stripped Go binary to fail" >&2
            exit 1
        fi
        grep -q 'Go binary without a usable symbol table' \
            "$TMP/gowarn_stripped.err"
    fi
fi

if [ "$(id -u)" -ne 0 ]; then
    echo "== tracing tests skipped (not root) =="
    exit 0
fi

echo "== trace simple =="
"$BIN" run -o "$TMP/simple.trace" --regex \
    --include '^(main|A[(]int[)]|B[(]int[)]|C[(]int[)])$' -- "$TMP/simple" \
    >/dev/null 2>"$TMP/simple.err"
grep -Eq '^[0-9]+\.[0-9]{9} [0-9]+ : 0 -> main' "$TMP/simple.trace"
grep -q ' : 1 -> C(int)' "$TMP/simple.trace"
grep -q ' : 2 -> B(int)' "$TMP/simple.trace"
grep -q ' : 3 -> A(int)' "$TMP/simple.trace"
grep -q ' : 3 <- A(int)' "$TMP/simple.trace"
grep -q ' : 0 <- main' "$TMP/simple.trace"
grep -q '0 lost' "$TMP/simple.err"

echo "== OTLP native file export =="
"$BIN" run -T --exporter otlp-json --export-file "$TMP/live.json" --regex \
    --include '^(main|A[(]int[)]|B[(]int[)]|C[(]int[)])$' -- "$TMP/simple" \
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

echo "== OTLP/HTTP protobuf export =="
if command -v python3 >/dev/null 2>&1 && "$BIN" --version | grep -q 'otlp protobuf: yes'; then
    python3 - "$BIN" "$TMP/simple" <<'PY'
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
    [binary, "run", "-T", "--exporter", "otlp-http",
     "--endpoint", f"http://127.0.0.1:{port}",
     "--regex", "--include", "^(main|C[(]int[)])$", "--", target],
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
"$BIN" attach -p "$attach_pid" \
    --exporter otlp-json --export-file "$TMP/attach.json" \
    --service-name attach-test --regex \
    --include '^(worker[(]int[)]|leaf[(]int[)])$' \
    >/dev/null 2>"$TMP/attach.err"
wait "$attach_pid" || true
grep -q 'OTLP .* span(s) exported' "$TMP/attach.err"
grep -q '"key":"callgraph.attach_mode","value":{"boolValue":true}' "$TMP/attach.json"
grep -q '"key":"callgraph.partial_stack","value":{"boolValue":true}' "$TMP/attach.json"
grep -q '"name":"worker(int)"' "$TMP/attach.json"

echo "== wall-clock timestamps =="
"$BIN" run -T -o "$TMP/wall.trace" --regex \
    --include '^(main|C[(]int[)])$' -- "$TMP/simple" >/dev/null 2>/dev/null
grep -Eq '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{9}[+-][0-9]{2}:[0-9]{2} [0-9]+ : 0 -> main' "$TMP/wall.trace"

echo "== indentation =="
"$BIN" run --indent 2 -o "$TMP/indent.trace" --regex \
    --include '^(main|A[(]int[)]|B[(]int[)]|C[(]int[)])$' -- "$TMP/simple" \
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
    "$BIN" run --show-args -o "$TMP/args.trace" --regex \
        --include '^(main|many[(]int, int, int, int, int, int, int[)]|ptr[(]char const[*], bool, char[)])$' \
        -- "$TMP/args" >/dev/null 2>/dev/null
    grep -q ' : 1 -> many(int, int, int, int, int, int, int) (a=1, b=2, c=3, d=4, e=5, f=6, g=7)' "$TMP/args.trace"
    grep -Eq " : 1 -> ptr[(]char const[*], bool, char[)] [(]s=0x[0-9a-f]+, flag=true, ch='A'[)]" "$TMP/args.trace"
    grep -q ' : 1 <- many(int, int, int, int, int, int, int)$' "$TMP/args.trace"

    echo "== function arguments with external debug info =="
    "$BIN" run --show-args -o "$TMP/detached-args.trace" --regex \
        --include '^(main|A[(]int[)])$' -- "$TMP/detached" \
        >/dev/null 2>/dev/null
    grep -q 'A(int) (x=3)' "$TMP/detached-args.trace"
else
    echo "== function arguments skipped (not x86-64) =="
fi

echo "== trace recursive =="
"$BIN" run -o "$TMP/rec.trace" --regex \
    --include '^(main|factorial[(]int[)])$' -- "$TMP/recursive" \
    >/dev/null 2>/dev/null
grep -q ' : 1 -> factorial(int)' "$TMP/rec.trace"
grep -q ' : 2 -> factorial(int)' "$TMP/rec.trace"
grep -q ' : 3 -> factorial(int)' "$TMP/rec.trace"
grep -q ' : 3 <- factorial(int)' "$TMP/rec.trace"

echo "== trace multithreaded =="
"$BIN" run -o "$TMP/mt.trace" --regex \
    --include '^(main|worker[(]int[)]|leaf[(]int[)])$' -- "$TMP/multithread" \
    >/dev/null 2>/dev/null
grep -q 'worker(int)' "$TMP/mt.trace"
grep -q 'leaf(int)' "$TMP/mt.trace"
awk '{print $2}' "$TMP/mt.trace" | sort -u | wc -l | grep -qx '3'

echo "== max depth =="
"$BIN" run -o "$TMP/depth.trace" --max-depth 1 --regex \
    --include '^(main|A[(]int[)]|B[(]int[)]|C[(]int[)])$' -- "$TMP/simple" \
    >/dev/null 2>/dev/null
! grep -q ' : 2 ' "$TMP/depth.trace"
grep -q ' : 1 -> C(int)' "$TMP/depth.trace"

echo "== latency histogram =="
"$BIN" run --histogram -o "$TMP/hist.trace" --regex \
    --include '^(main|A[(]int[)]|B[(]int[)]|C[(]int[)])$' -- "$TMP/simple" \
    >/dev/null 2>/dev/null
grep -q '^=== thread [0-9][0-9]* ===$' "$TMP/hist.trace"
grep -q '^Tree:$' "$TMP/hist.trace"
grep -q '^Histograms:$' "$TMP/hist.trace"
grep -Fqx '0. main' "$TMP/hist.trace"
grep -Fqx '1. C(int)' "$TMP/hist.trace"
grep -Fqx '└── C(int)' "$TMP/hist.trace"
grep -q '├── ' "$TMP/hist.trace"
grep -q '^   calls=1  total=' "$TMP/hist.trace"
grep -Eq '^   \[ .*\)  [0-9]+  -' "$TMP/hist.trace"
grep -q ' : 0 -> main' "$TMP/hist.trace"
tree_line=$(grep -n '^Tree:$' "$TMP/hist.trace" | head -1 | cut -d: -f1)
hist_line=$(grep -n '^Histograms:$' "$TMP/hist.trace" | head -1 | cut -d: -f1)
[ "$tree_line" -lt "$hist_line" ]
# Without the option the report is absent.
! grep -q '^=== thread ' "$TMP/simple.trace"

echo "== latency histogram: one pair per root =="
"$BIN" run --histogram -o "$TMP/hist_mt.trace" --regex \
    --include '^(main|worker[(]int[)]|leaf[(]int[)])$' -- "$TMP/multithread" \
    >/dev/null 2>/dev/null
sections=$(grep -c '^=== thread ' "$TMP/hist_mt.trace" || true)
[ "$sections" -ge 2 ]

echo "== latency histogram: tree and histograms paired per root =="
"$BIN" run --histogram -o "$TMP/hist_roots.trace" --regex \
    --include '^(task_a[(]int[)]|task_b[(]int[)]|leaf[(]int[)])$' -- "$TMP/tworoots" \
    >/dev/null 2>/dev/null
[ "$(grep -c '^Tree:$' "$TMP/hist_roots.trace")" -eq 2 ]
[ "$(grep -c '^Histograms:$' "$TMP/hist_roots.trace")" -eq 2 ]
[ "$(grep -E '^(Tree|Histograms):$' "$TMP/hist_roots.trace" | tr '\n' ' ')" = \
  "Tree: Histograms: Tree: Histograms: " ]
# Each root keeps its own leaf entry: four single-call blocks, not a merged
# two-call leaf in one thread-wide histogram section.
[ "$(grep -c '^   calls=1 ' "$TMP/hist_roots.trace")" -eq 4 ]

echo "== exception-safe return mode =="
if "$BIN" run --return-mode ret --dry-run -- "$TMP/exceptions" >/dev/null 2>&1; then
    "$BIN" run --return-mode ret -o "$TMP/exc.trace" --regex \
        --include '^(main|outer[(][)]|middle[(][)]|inner[(][)])$' -- "$TMP/exceptions" \
        >/dev/null 2>"$TMP/exc.err"
    grep -q ' : 3 -> inner()' "$TMP/exc.trace"
    grep -q ' : 1 <- outer()' "$TMP/exc.trace"
    grep -q ' : 0 <- main' "$TMP/exc.trace"
    grep -q '2 desync' "$TMP/exc.err"
else
    echo "libopcodes not available; skipping ret mode"
fi

echo "== longjmp resynchronisation =="
"$BIN" run -o "$TMP/lj.trace" --regex \
    --include '^(main|error_path[(][)]|deep[(]int[)])$' -- "$TMP/longjmp" \
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
"$BIN" run --no-rsp-resync -o "$TMP/lj_norsp.trace" --regex \
    --include '^(main|error_path[(][)]|deep[(]int[)])$' -- "$TMP/longjmp" \
    >/dev/null 2>"$TMP/lj_norsp.err"
awk '$5 == "->" && $6 == "error_path()" {
         if (n++ && $4 <= prev) bad = 1
         prev = $4
     }
     END { exit (n == 3 && !bad) ? 0 : 1 }' "$TMP/lj_norsp.trace"

echo "== stackful coroutine (ucontext) =="
"$BIN" run -o "$TMP/uctx.trace" --regex \
    --include '^(main|fiber_body[(][)]|leaf[(][)])$' -- "$TMP/ucontext" \
    >/dev/null 2>"$TMP/uctx.err"
# The fiber runs on a separate stack.  Switching back to the main stack looks
# like an unwind, so the suspended fiber_body frame is dropped and the main
# stack call is attributed to main.
grep -Eq '[1-9][0-9]* desync' "$TMP/uctx.err"
[ "$(grep -c ' : 2 -> leaf()' "$TMP/uctx.trace")" -eq 1 ]

# --no-rsp-resync keeps the suspended frame, so every leaf nests under
# fiber_body.
"$BIN" run --no-rsp-resync -o "$TMP/uctx_norsp.trace" --regex \
    --include '^(main|fiber_body[(][)]|leaf[(][)])$' -- "$TMP/ucontext" \
    >/dev/null 2>"$TMP/uctx_norsp.err"
[ "$(grep -c ' : 2 -> leaf()' "$TMP/uctx_norsp.trace")" -eq 3 ]

# uretprobes lose the fiber's return across the switch, so ret mode is needed
# for complete pairing.  Together with --no-rsp-resync nothing is desynced.
if "$BIN" run --return-mode ret --dry-run -- "$TMP/ucontext" >/dev/null 2>&1; then
    "$BIN" run --return-mode ret --no-rsp-resync -o "$TMP/uctx_ret.trace" \
        --regex --include '^(main|fiber_body[(][)]|leaf[(][)])$' \
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
"$BIN" run --all-modules -o "$TMP/lib.trace" --regex --include '^foo' \
    -- "$TMP/use_lib" >/dev/null 2>/dev/null
grep -q 'foo(int)' "$TMP/lib.trace"
grep -q ' <- foo(int)' "$TMP/lib.trace"

echo "all integration tests passed"
