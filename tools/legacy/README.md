# gen_callgraph.py

Generate a [bpftrace](https://github.com/bpftrace/bpftrace) script that logs
`>>` / `<<` for **every function** in an executable, using the symbols
reported by `nm -C`.

Each function gets a `uprobe`/`uretprobe` pair. The output looks like:

```
1234567890 4242 : 0 >> main
1234567895 4242 : 1 >> B
1234567897 4242 : 2 >> A
1234567900 4242 : 2 << A
1234567902 4242 : 1 << B
1234567905 4242 : 0 << main
```

The middle number is a **per-thread call depth** stored in `@depth[tid]`:
on `>>` it is printed *before* incrementing, on `<<` *after*
decrementing (matching the original template).

## Requirements

| Tool | Purpose |
| --- | --- |
| Python 3.8+ | runs the generator |
| `nm`, `readelf` (binutils) | read the executable's symbol table / section flags |
| `bpftrace` | runs the generated script |
| root (or `CAP_BPF` + `CAP_PERFMON` + `CAP_SYS_ADMIN`) | uprobes |

The target must still have its `.symtab` — i.e. **do not `strip` it**. Debug
info (`-g`) is not required; the symbol table is enough.

## Quick start

```bash
# 1. Build a program with symbols
g++ -O0 -g -o demo demo.cpp

# 2. Generate the bpftrace script
python3 gen_callgraph.py ./demo > demo.bt

# 3. Run it (uprobes need privileges)
sudo bpftrace demo.bt
```

Then run `./demo` in another terminal (or start it from a wrapper). The
generated probes fire whenever any traced thread enters/leaves a function.

### Example

`demo.cpp`:

```cpp
#include <cstdio>

int A(int x) { return x + 1; }
int B(int x) { return A(x) * 2; }
int main() { std::printf("%d\n", B(3)); return 0; }
```

`demo.bt` (abridged):

```bpftrace
#!/usr/bin/env bpftrace
/*
 * Auto-generated call tracer (gen_callgraph.py).
 *
 *   target    : /home/ben/github/callgraph/demo
 *   functions : 10
 * ...
 */

/*
 * Function A(int)
 */
uprobe:/home/ben/github/callgraph/demo:_Z1Ai
{
    printf("%llu %d : %d >> A\n", nsecs, tid, @depth[tid]);
    @depth[tid] = @depth[tid] + 1;
}

uretprobe:/home/ben/github/callgraph/demo:_Z1Ai
{
    if (@depth[tid] > 0) {
        @depth[tid] = @depth[tid] - 1;
    }
    printf("%llu %d : %d << A\n", nsecs, tid, @depth[tid]);
}
```

Note the probe uses the **mangled** name `_Z1Ai`; `nm -C` is only used for the
human-readable comment and log label.

## Command line

```
usage: gen_callgraph.py [-h] [-o FILE] [--probe-path PATH]
                        [--label {short,full,mangled}] [--max-name-len N]
                        [--include REGEX] [--exclude REGEX] [--global-only]
                        [--split DIR]
                        executable
```

| Option | Description |
| --- | --- |
| `executable` | ELF executable to trace (required) |
| `-o, --output FILE` | write the combined script to `FILE` instead of stdout (`-` = stdout) |
| `--probe-path PATH` | path inserted into the probe specs (default: absolute path of the executable) |
| `--label {short,full,mangled}` | text printed after `>>`/`<<` (default: `short`) |
| `--max-name-len N` | truncate labels to `N` chars, `0` = no limit (default: `120`) |
| `--include REGEX` | only trace functions whose demangled **or** mangled name matches |
| `--exclude REGEX` | skip functions whose demangled **or** mangled name matches |
| `--global-only` | only trace global/weak functions (`nm` types `T` and `W`) |
| `--split DIR` | also write one complete `.bt` file per function into `DIR` |

`--label` values:

- `short` — demangled name without the parameter list (`demo::add`)
- `full` — full demangled signature (`demo::add(int, int)`)
- `mangled` — raw symbol (`_ZN4demo3addEii`)

## Common recipes

### Trace only your own code

C++ executables also contain startup helpers (`_init`, `_fini`, `_start`,
`frame_dummy`, ...). Narrow the output:

```bash
python3 gen_callgraph.py ./demo --include '^(main|demo::)' > demo.bt
```

or drop standard-library symbols:

```bash
python3 gen_callgraph.py ./demo --exclude '^std::|^__gnu_cxx::' > demo.bt
```

### Trace only exported functions

```bash
python3 gen_callgraph.py ./libfoo.so --global-only > foo.bt
```

(`nm` types `T` and `W`; local symbols such as `static` helpers are skipped.)

### Match the `./demo` style probe path

By default the generator writes an absolute path so the script works from any
directory. Use a relative path if you prefer the template's style:

```bash
python3 gen_callgraph.py ./demo --probe-path ./demo > demo.bt
```

### One script per function

```bash
python3 gen_callgraph.py ./demo --split probes/
ls probes/          # 0001_A.bt 0002_B.bt ...
```

With `--split` and no `-o`, the combined script is not printed; a summary is
shown instead. Combine with `-o` to get both.

### Use a different label style

```bash
python3 gen_callgraph.py ./demo --label full --max-name-len 80
```

## How it works

1. `nm --defined-only` lists symbols with their mangled names.
2. `nm --defined-only -C` lists the same symbols demangled. Both listings are
   in the same order, so they are paired line by line (falling back to
   address matching if the counts ever differ).
3. `readelf -SW` gives the executable section ranges. `nm` reports weak data
   symbols such as `data_start` as type `W`, which looks like a weak function,
   so symbols outside executable sections are dropped.
4. For each remaining function, a `uprobe`/`uretprobe` pair is emitted. The
   `uprobe` prints the current depth and increments it; the `uretprobe`
   decrements (never below zero) and prints the resulting depth.
5. Names embedded in `printf` are escaped (`%` → `%%`, quotes, backslashes);
   names that cannot be represented safely in a probe are skipped with a
   comment.

Duplicate symbol names (for example two `static` functions called `helper`
in different translation units) are emitted only once, because bpftrace
resolves a probe name to a single address; a warning is printed to stderr.

## Limitations and troubleshooting

**`error: no functions matched`** — the executable is stripped (no `.symtab`)
or your `--include`/`--exclude` filters removed everything. Check manually:

```bash
nm -C --defined-only ./demo | grep ' T '
```

**`Could not resolve symbol` / probe fails to attach** — the symbol may have
been inlined away, stripped, or the probe path is wrong. Prefer the default
absolute path, or pass the exact path with `--probe-path`.

**Permission denied / "bpftrace currently only supports running as the root
user"** — run with `sudo`, or grant the required capabilities.

**BTF / kernel header errors on WSL** — bpftrace needs the running kernel's BTF
(`/sys/kernel/btf/vmlinux`) or matching kernel headers. Update WSL/bpftrace, or
run on a kernel that provides BTF. This is an environment issue, not a
generator issue.

**Missing `<<` lines / depth never returns to 0** — a function that never
returns normally (`exit()`, `longjmp()`, an uncaught exception, `_start`)
leaves `@depth[tid]` elevated. Exclude such functions if it matters:

```bash
python3 gen_callgraph.py ./demo --exclude '^_start$|^exit$' > demo.bt
```

**The log is huge** — tracing *every* function of a large C++ binary is
expensive (thousands of probes, a `printf` per call). Use `--include`,
`--exclude`, or `--split` to reduce the set.

**Labels for `operator%` show `operator%%`** — the `%` is escaped so
bpftrace's `printf` prints a literal `%`. Use `--label full`/`--label mangled`
if you prefer different text.

**Map growth** — `@depth` keeps one entry per thread for the lifetime of the
bpftrace process; it is discarded when bpftrace exits.

## Files

```
gen_callgraph.py   generator
README.md          this file
```
