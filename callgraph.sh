#!/usr/bin/env bash
# MIT License
#
# Copyright (c) 2026 callgraph contributors
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
# callgraph.sh - orchestration wrapper.
#
# This script contains no analysis logic.  It decides whether the tracer needs
# static call-graph facts, asks callgraph-disasm for them, and passes the
# resulting JSON path to the tracer with --static-graph.  The tracer and the
# generator are ordinary programs; this wrapper never gates or hides them.

set -euo pipefail

# The binaries are installed next to the real script.  Resolve this script
# through symlinks (and through PATH when invoked by name) so a symlinked
# wrapper still finds its own directory.
resolve_self_dir() {
    local self=${BASH_SOURCE[0]}
    if [[ $self != */* ]]; then
        local found
        found=$(command -v -- "$self" 2>/dev/null) || true
        if [[ -n $found ]]; then
            self=$found
        fi
    fi
    while [[ -L $self ]]; do
        local link
        link=$(readlink -- "$self") || break
        if [[ $link != /* ]]; then
            link=$(dirname -- "$self")/$link
        fi
        self=$link
    done
    cd -- "$(dirname -- "$self")" && pwd -P
}

self_dir=$(resolve_self_dir)
callgraph=${CALLGRAPH:-"$self_dir/callgraph"}
callgraph_disasm=${CALLGRAPH_DISASM:-"$self_dir/callgraph-disasm"}

usage() {
    cat <<'EOF'
Usage:
  callgraph.sh run    [tracer options] -- PROGRAM [ARGS...]
  callgraph.sh attach [tracer options] -p PID
  callgraph.sh export --static [options] MODULE
  callgraph.sh export --otel|--flame [options]
  callgraph.sh disasm [callgraph-disasm options] MODULE

Wrapper options (any mode except disasm):
      --graph-in FILE    reuse existing facts and skip generation
      --graph-out FILE   keep the generated facts at FILE
      --no-graph         never generate facts; pass arguments through

Facts are generated automatically for:
  run/attach --trace-depth N (N >= 0) or --return-mode=ret
  export --static

--all-modules is forwarded to callgraph-disasm as well as to the tracer, so
the facts cover the target's static DT_NEEDED closure.  Modules opened with
dlopen have no facts and degrade with a tracer warning.
EOF
}

die() {
    printf 'callgraph.sh: %s\n' "$*" >&2
    exit 1
}

if (($# == 0)); then
    usage >&2
    exit 2
fi

case $1 in
    -h | --help | help)
        usage
        exit 0
        ;;
    --version)
        "$callgraph" --version
        if [[ -x $callgraph_disasm ]]; then
            "$callgraph_disasm" --version
        fi
        exit 0
        ;;
    run | attach | export | disasm) ;;
    *)
        usage >&2
        exit 2
        ;;
esac

mode=$1
shift

# Pull the wrapper-only options out of the argument list.  Everything after
# "--" belongs to the traced program and is never inspected.
graph_in=
graph_out=
no_graph=0
filtered=()
end_of_options=0
while (($#)); do
    if ((end_of_options)); then
        filtered+=("$1")
        shift
        continue
    fi
    case $1 in
        --)
            end_of_options=1
            filtered+=("$1")
            shift
            ;;
        --graph-in)
            (($# >= 2)) || die "--graph-in requires a value"
            graph_in=$2
            shift 2
            ;;
        --graph-in=*)
            graph_in=${1#*=}
            shift
            ;;
        --graph-out)
            (($# >= 2)) || die "--graph-out requires a value"
            graph_out=$2
            shift 2
            ;;
        --graph-out=*)
            graph_out=${1#*=}
            shift
            ;;
        --no-graph)
            no_graph=1
            shift
            ;;
        *)
            filtered+=("$1")
            shift
            ;;
    esac
done

if ((${#filtered[@]})); then
    set -- "${filtered[@]}"
else
    set --
fi

if [[ $mode == disasm ]]; then
    [[ -x $callgraph_disasm ]] || die "callgraph-disasm not found at $callgraph_disasm"
    exec "$callgraph_disasm" "$@"
fi

# Scans arguments for tracer flags that need facts.  Sets trace_depth,
# return_mode, all_modules and user_static_graph.
scan_flags() {
    trace_depth=
    return_mode=
    all_modules=0
    user_static_graph=0
    local args=("$@")
    local i arg
    for ((i = 0; i < ${#args[@]}; i++)); do
        arg=${args[i]}
        [[ $arg == -- ]] && break
        case $arg in
            --trace-depth=*) trace_depth=${arg#*=} ;;
            --trace-depth) trace_depth=${args[i + 1]:-} ;;
            --return-mode=*) return_mode=${arg#*=} ;;
            --return-mode) return_mode=${args[i + 1]:-} ;;
            --all-modules) all_modules=1 ;;
            --static-graph=*) user_static_graph=1 ;;
            --static-graph) user_static_graph=1 ;;
        esac
    done
}

needs_graph() {
    [[ $return_mode == ret ]] && return 0
    [[ -n $trace_depth && $trace_depth != -1 ]] && return 0
    return 1
}

resolve_program() {
    local program=$1
    if [[ $program == */* ]]; then
        printf '%s\n' "$program"
        return
    fi
    command -v -- "$program" 2>/dev/null || printf '%s\n' "$program"
}

# Prints the executable path for a PID, or fails.
pid_exe() {
    local pid=$1
    [[ -n $pid ]] || die "attach requires -p PID"
    [[ -e /proc/$pid/exe ]] || die "cannot read /proc/$pid/exe"
    readlink -f -- "/proc/$pid/exe"
}

generate_facts() {
    local module=$1
    [[ -n $module ]] || die "cannot determine the module to analyze"
    [[ -x $callgraph_disasm ]] || die "callgraph-disasm not found at $callgraph_disasm"

    local facts=$graph_out
    local cleanup=0
    if [[ -z $facts ]]; then
        local dir
        dir=$(mktemp -d "${TMPDIR:-/tmp}/callgraph-facts.XXXXXX")
        facts=$dir/facts.json
        cleanup=1
        # shellcheck disable=SC2064
        trap "rm -rf -- '$dir'" EXIT
    fi

    local args=()
    ((all_modules)) && args+=(--all-modules)
    args+=("$module" -o "$facts")

    "$callgraph_disasm" "${args[@]}"
    if ((cleanup == 0)); then
        printf 'callgraph.sh: facts written to %s\n' "$facts" >&2
    fi
    facts_path=$facts
}

facts_path=

if [[ $mode == export ]]; then
    scan_flags "$@"
    # Detect the export sub-mode.
    export_static=0
    for arg in "$@"; do
        case $arg in
            --static) export_static=1 ;;
            --otel | --flame) export_static=0 ;;
        esac
    done

    if ((export_static)); then
        # Find the module positional while skipping option values.
        module=
        expect_value=0
        for arg in "$@"; do
            if ((expect_value)); then
                expect_value=0
                continue
            fi
            case $arg in
                -o | --output | --root-scope | --static-graph)
                    expect_value=1
                    ;;
                -*) ;;
                *) module=$arg ;;
            esac
        done

        if ((user_static_graph)); then
            exec "$callgraph" export "$@"
        fi

        if ((no_graph == 0)); then
            if [[ -n $graph_in ]]; then
                facts_path=$graph_in
            else
                generate_facts "$module"
            fi

            # Rebuild the argument list without the positional MODULE: the
            # tracer takes the facts path, not an ELF path.
            rebuilt=()
            expect_value=0
            for arg in "$@"; do
                if ((expect_value)); then
                    expect_value=0
                    rebuilt+=("$arg")
                    continue
                fi
                case $arg in
                    -o | --output | --root-scope | --static-graph)
                        expect_value=1
                        rebuilt+=("$arg")
                        ;;
                    --all-modules)
                        # Facts already cover the closure; the tracer has no
                        # such flag in static export mode.
                        ;;
                    -*)
                        rebuilt+=("$arg")
                        ;;
                    *)
                        # Drop the positional MODULE.
                        ;;
                esac
            done
            exec "$callgraph" export "${rebuilt[@]}" --static-graph "$facts_path"
        fi
    fi

    exec "$callgraph" export "$@"
fi

# run / attach
scan_flags "$@"

if ((user_static_graph)) || ((no_graph)); then
    exec "$callgraph" "$mode" "$@"
fi

if [[ -n $graph_in ]]; then
    facts_path=$graph_in
elif needs_graph; then
    if [[ $mode == run ]]; then
        module=
        saw_separator=0
        args=("$@")
        for ((i = 0; i < ${#args[@]}; i++)); do
            if [[ ${args[i]} == -- ]]; then
                saw_separator=1
                module=${args[i + 1]:-}
                break
            fi
        done
        ((saw_separator)) || die "run requires '-- PROGRAM' to locate the target"
        module=$(resolve_program "$module")
    else
        pid=
        args=("$@")
        for ((i = 0; i < ${#args[@]}; i++)); do
            case ${args[i]} in
                -p | --pid) pid=${args[i + 1]:-} ;;
                --pid=*) pid=${args[i]#*=} ;;
            esac
        done
        module=$(pid_exe "$pid")
    fi
    generate_facts "$module"
else
    exec "$callgraph" "$mode" "$@"
fi

if [[ $mode == run ]]; then
    # --static-graph must precede the "--" separator.
    final=()
    inserted=0
    for arg in "$@"; do
        if [[ $arg == -- ]] && ((inserted == 0)); then
            final+=(--static-graph "$facts_path")
            inserted=1
        fi
        final+=("$arg")
    done
    exec "$callgraph" run "${final[@]}"
fi

exec "$callgraph" attach "$@" --static-graph "$facts_path"
