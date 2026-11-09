#!/usr/bin/env python3
"""Generate a bpftrace call-tracing script from an executable's symbol table.

For every function reported by ``nm -C --defined-only <executable>`` the
generated script installs a matching ``uprobe``/``uretprobe`` pair that logs

    <nsecs> <tid> : <depth> >> <name>
    <nsecs> <tid> : <depth> << <name>

where ``<depth>`` is a per-thread call depth kept in ``@depth[tid]``.  The
number printed is the depth *before* entering (``>>``) and the depth *after*
leaving (``<<``), exactly like the original template.

The probes must use the *mangled* symbol names (``_Z1Av``, not ``A()``),
because that is what bpftrace resolves in the symbol table; ``nm -C`` is used
for the human readable names in comments and log messages.

Examples
--------
    python3 gen_callgraph.py ./demo > demo.bt
    sudo bpftrace demo.bt

    python3 gen_callgraph.py ./demo -o demo.bt --label full
    python3 gen_callgraph.py ./demo --split probes/ --exclude '^std::'
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

# nm(1) symbol types that denote code: global/local text and weak functions.
FUNCTION_TYPES = frozenset("TtWw")

# "0000000000001139 T _Z1Av"  (the name may contain spaces when demangled).
NM_LINE_RE = re.compile(r"^\s*([0-9a-fA-F]+)\s+([A-Za-z?])\s+(.+?)\s*$")

# Characters we are willing to put into a bpftrace probe specification.
SAFE_SYMBOL_RE = re.compile(r"[A-Za-z0-9_$.]+")

HEADER = """\
#!/usr/bin/env bpftrace
/*
 * Auto-generated call tracer (gen_callgraph.py).
 *
 *   target    : {target}
 *   functions : {count}
 *
 * Every function gets a uprobe/uretprobe pair.  The per-thread call depth is
 * kept in @depth[tid]; the number printed is the depth *before* entering on
 * >> and *after* leaving on <<.
 *
 * Caveat: a function that never returns normally (exit(), longjmp(), an
 * uncaught exception, ...) leaves @depth[tid] permanently elevated.
 */
"""

FUNC_TEMPLATE = """
/*
 * Function {comment}
 */
uprobe:{target}:{symbol}
{{
    printf("%llu %d : %d >> {label}\\n", nsecs, tid, @depth[tid]);
    @depth[tid] = @depth[tid] + 1;
}}

uretprobe:{target}:{symbol}
{{
    if (@depth[tid] > 0) {{
        @depth[tid] = @depth[tid] - 1;
    }}
    printf("%llu %d : %d << {label}\\n", nsecs, tid, @depth[tid]);
}}
"""


def run_nm(executable: Path, demangle: bool) -> str:
    """Return ``nm --defined-only [-C] -- <executable>`` output."""
    cmd = ["nm", "--defined-only"]
    if demangle:
        cmd.append("-C")
    cmd.extend(["--", str(executable)])
    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
    except FileNotFoundError:
        sys.exit("error: 'nm' not found; install binutils")
    if result.returncode != 0:
        sys.exit(f"error: {' '.join(cmd)} failed:\n{result.stderr.strip()}")
    return result.stdout


def parse_symbols(output: str) -> list[tuple[int, str, str]]:
    """Parse nm output into ``(address, type, name)`` for code symbols."""
    symbols = []
    for line in output.splitlines():
        match = NM_LINE_RE.match(line)
        if not match:
            continue
        address, kind, name = match.groups()
        if kind not in FUNCTION_TYPES:
            continue
        symbols.append((int(address, 16), kind, name))
    return symbols


def executable_ranges(executable: Path) -> list[tuple[int, int]] | None:
    """Return ``(start, end)`` address ranges of executable sections.

    ``nm`` reports weak *data* symbols (for example ``data_start``) with the
    same ``W`` type as weak functions, so use the section flags to keep only
    symbols that actually live in executable code.  Returns ``None`` when
    readelf is unavailable and the caller should skip the check.
    """
    cmd = ["readelf", "-SW", "--", str(executable)]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True)
    except FileNotFoundError:
        print(
            "warning: 'readelf' not found; data symbols may be included",
            file=sys.stderr,
        )
        return None
    if result.returncode != 0:
        print(
            "warning: 'readelf -SW' failed; data symbols may be included",
            file=sys.stderr,
        )
        return None

    ranges = []
    for line in result.stdout.splitlines():
        fields = line.split()
        # readelf pads the section number: "[ 1]" splits into "[", "1]".
        if len(fields) > 1 and fields[0] == "[":
            fields = [fields[0] + fields[1]] + fields[2:]
        if len(fields) < 8 or not fields[0].startswith("["):
            continue
        try:
            address = int(fields[3], 16)
            size = int(fields[5], 16)
        except ValueError:
            continue
        if "X" in fields[7]:
            ranges.append((address, address + size))
    return ranges


def in_executable(address: int, ranges: list[tuple[int, int]]) -> bool:
    return any(start <= address < end for start, end in ranges)


def collect_functions(executable: Path) -> list[tuple[str, str, str]]:
    """Pair mangled names (for probes) with demangled names (for display).

    Returns a list of ``(mangled, demangled, nm_type)`` in address order.
    """
    mangled = parse_symbols(run_nm(executable, demangle=False))
    pretty = parse_symbols(run_nm(executable, demangle=True))

    ranges = executable_ranges(executable)
    if ranges is not None:
        mangled = [sym for sym in mangled if in_executable(sym[0], ranges)]
        pretty = [sym for sym in pretty if in_executable(sym[0], ranges)]

    if len(mangled) == len(pretty) and all(
        m[0] == p[0] and m[1] == p[1] for m, p in zip(mangled, pretty)
    ):
        # Demangling only rewrites names, so both listings line up exactly.
        pairs = [(m[2], p[2], m[1]) for m, p in zip(mangled, pretty)]
    else:
        # Fallback: match by address.  Aliases share an address and probing
        # either name reaches the same code, so any pairing is good enough.
        by_address: dict[int, list[tuple[str, str]]] = {}
        for address, kind, name in mangled:
            by_address.setdefault(address, []).append((name, kind))
        pairs = []
        for address, _kind, name in pretty:
            candidates = by_address.get(address)
            if candidates:
                mangled_name, mangled_kind = candidates.pop(0)
                pairs.append((mangled_name, name, mangled_kind))

    functions = []
    seen = set()
    duplicates = 0
    for mangled_name, pretty_name, kind in pairs:
        if mangled_name in seen:
            # bpftrace resolves a probe name to a single address, so two
            # local static functions with the same name cannot both be
            # addressed by name.  Keep the first one and warn.
            duplicates += 1
            continue
        seen.add(mangled_name)
        functions.append((mangled_name, pretty_name, kind))

    if duplicates:
        print(
            f"warning: skipped {duplicates} duplicate symbol name(s); "
            "bpftrace can only resolve one address per name",
            file=sys.stderr,
        )
    return functions


def short_name(demangled: str) -> str:
    """Strip the parameter list from a demangled function name.

    Handles ``operator()`` (its parentheses belong to the name) and skips
    parentheses nested inside template arguments.
    """
    angle = 0
    paren = 0
    for index, char in enumerate(demangled):
        if char == "<":
            angle += 1
        elif char == ">":
            angle = max(0, angle - 1)
        elif char == "(":
            if angle == 0 and paren == 0:
                if demangled[max(0, index - len("operator")):index] == "operator":
                    paren = 1
                    continue
                return demangled[:index]
            paren += 1
        elif char == ")":
            paren = max(0, paren - 1)
    return demangled


def label_for(pretty: str, mangled: str, mode: str) -> str:
    if mode == "mangled":
        return mangled
    if mode == "full":
        return pretty
    return short_name(pretty)


def escape_printf(text: str) -> str:
    """Escape a name so it can be embedded in a bpftrace printf string."""
    return (
        text.replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("%", "%%")
        .replace("\n", "\\n")
        .replace("\r", "\\r")
        .replace("\t", "\\t")
    )


def comment_text(text: str) -> str:
    return text.replace("*/", "* /").replace("\n", " ").replace("\r", " ")


def truncate(text: str, limit: int) -> str:
    if limit and len(text) > limit:
        return text[: max(0, limit - 3)] + "..."
    return text


def render(
    functions: list[tuple[str, str, str]],
    target: str,
    max_name_len: int,
    label_mode: str,
) -> str:
    blocks = []
    emitted = 0
    for mangled, pretty, _kind in functions:
        if not SAFE_SYMBOL_RE.fullmatch(mangled):
            blocks.append(
                "\n/* skipped %s: symbol %r is not usable in a bpftrace probe */\n"
                % (comment_text(pretty), mangled)
            )
            continue
        label = escape_printf(truncate(label_for(pretty, mangled, label_mode), max_name_len))
        blocks.append(
            FUNC_TEMPLATE.format(
                comment=comment_text(pretty),
                target=target,
                symbol=mangled,
                label=label,
            )
        )
        emitted += 1
    return HEADER.format(target=target, count=emitted) + "".join(blocks)


def write_script(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    try:
        path.chmod(path.stat().st_mode | 0o111)
    except OSError:
        pass


def write_split(
    directory: Path,
    functions: list[tuple[str, str, str]],
    target: str,
    max_name_len: int,
    label_mode: str,
) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    for index, function in enumerate(functions, 1):
        pretty = function[1]
        slug = re.sub(r"[^A-Za-z0-9_.-]+", "_", short_name(pretty))[:80].strip("_")
        path = directory / f"{index:04d}_{slug or 'function'}.bt"
        write_script(path, render([function], target, max_name_len, label_mode))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__.splitlines()[0],
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("executable", help="ELF executable to trace")
    parser.add_argument(
        "-o",
        "--output",
        metavar="FILE",
        help="write the combined script here (default: stdout; '-' means stdout)",
    )
    parser.add_argument(
        "--probe-path",
        metavar="PATH",
        help="path to put in the uprobe specs (default: absolute path of EXECUTABLE)",
    )
    parser.add_argument(
        "--label",
        choices=("short", "full", "mangled"),
        default="short",
        help="what to print after >>/<< (default: %(default)s)",
    )
    parser.add_argument(
        "--max-name-len",
        type=int,
        default=120,
        metavar="N",
        help="truncate names in log messages to N chars, 0 = no limit (default: %(default)s)",
    )
    parser.add_argument(
        "--include",
        metavar="REGEX",
        help="only trace functions whose demangled or mangled name matches REGEX",
    )
    parser.add_argument(
        "--exclude",
        metavar="REGEX",
        help="skip functions whose demangled or mangled name matches REGEX",
    )
    parser.add_argument(
        "--global-only",
        action="store_true",
        help="only trace global/weak functions (nm types T and W)",
    )
    parser.add_argument(
        "--split",
        metavar="DIR",
        help="also write one complete script per function into DIR",
    )
    args = parser.parse_args(argv)

    executable = Path(args.executable)
    if not executable.is_file():
        parser.error(f"not a file: {executable}")

    target = args.probe_path or str(executable.resolve())
    if re.search(r"[\s:]", target):
        print(
            "warning: probe path contains whitespace or ':', which bpftrace may "
            f"parse incorrectly: {target}",
            file=sys.stderr,
        )

    functions = collect_functions(executable)
    if args.global_only:
        functions = [fn for fn in functions if fn[2] in "TW"]

    try:
        include = re.compile(args.include) if args.include else None
        exclude = re.compile(args.exclude) if args.exclude else None
    except re.error as exc:
        parser.error(f"invalid regular expression: {exc}")

    def wanted(function: tuple[str, str, str]) -> bool:
        # Test the demangled and mangled names separately so anchored patterns
        # such as '^main$' behave as expected.
        pretty, mangled = function[1], function[0]
        if include is not None and not (
            include.search(pretty) or include.search(mangled)
        ):
            return False
        if exclude is not None and (exclude.search(pretty) or exclude.search(mangled)):
            return False
        return True

    functions = [fn for fn in functions if wanted(fn)]
    if not functions:
        sys.exit(
            "error: no functions matched.  Is the executable stripped (no "
            ".symtab)?  Try `nm -C --defined-only <executable>` by hand."
        )

    if args.split:
        write_split(Path(args.split), functions, target, args.max_name_len, args.label)

    if args.output and args.output != "-":
        write_script(Path(args.output), render(functions, target, args.max_name_len, args.label))
    elif args.output == "-" or not args.split:
        sys.stdout.write(render(functions, target, args.max_name_len, args.label))
    else:
        print(f"wrote {len(functions)} per-function scripts to {args.split}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
