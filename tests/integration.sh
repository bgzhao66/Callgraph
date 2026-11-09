#!/usr/bin/env bash
set -euo pipefail

BIN=${1:?usage: integration.sh /path/to/callgraph}
ROOT=$(cd "$(dirname "$0")/.." && pwd)
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

g++ -O0 -g -o "$TMP/simple" "$ROOT/examples/simple.cpp"
g++ -O0 -g -o "$TMP/recursive" "$ROOT/examples/recursive.cpp"
g++ -O0 -g -pthread -o "$TMP/multithread" "$ROOT/examples/multithread.cpp"
g++ -O0 -g -o "$TMP/exceptions" "$ROOT/examples/exceptions.cpp"

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

if [ "$(id -u)" -ne 0 ]; then
    echo "== tracing tests skipped (not root) =="
    exit 0
fi

echo "== trace simple =="
"$BIN" run -o "$TMP/simple.trace" --regex \
    --include '^(main|A[(]int[)]|B[(]int[)]|C[(]int[)])$' -- "$TMP/simple" \
    >/dev/null 2>"$TMP/simple.err"
grep -q ' : 0 -> main' "$TMP/simple.trace"
grep -q ' : 1 -> C(int)' "$TMP/simple.trace"
grep -q ' : 2 -> B(int)' "$TMP/simple.trace"
grep -q ' : 3 -> A(int)' "$TMP/simple.trace"
grep -q ' : 3 <- A(int)' "$TMP/simple.trace"
grep -q ' : 0 <- main' "$TMP/simple.trace"
grep -q '0 lost' "$TMP/simple.err"

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
