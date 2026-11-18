# Static graph facts format

`callgraph-disasm` writes one JSON document describing the static call graph of
one or more ELF modules. The tracer programs read it with `--static-graph FILE`
for three features:

- `--trace-depth N >= 0` probe pruning and root selection
- `--return-mode=ret` return-instruction offsets
- `export --static` tree rendering

The tracer never disassembles anything. The format is the only interface
between the two programs, and it is deliberately small.

## Versioning

- `format` is the literal string `callgraph-static-graph`.
- `version` is an integer. This document describes version `1`.
- A reader must reject a missing `format`, a different `format`, a missing
  `version`, or any `version` it does not know. It must not guess.
- Additive fields may appear within a version; readers ignore unknown keys.
  Removing a field, renaming a field, or changing a field's meaning requires a
  new version.

## Document

```json
{
  "format": "callgraph-static-graph",
  "version": 1,
  "generator": { "name": "callgraph-disasm", "version": "0.1.0" },
  "modules": [ /* module objects */ ]
}
```

`generator` is informational and may be omitted by other producers.

## Module

```json
{
  "path": "/abs/path/app",
  "build_id": "991122deee320fecee93c72998754957e53588c5",
  "arch": "x86_64",
  "is_64bit": true,
  "prunable": true,
  "prune_reason": "",
  "functions": [ /* function objects */ ],
  "edges": [[1, 2], [2], []],
  "roots": [0]
}
```

| Field | Meaning |
|---|---|
| `path` | Canonical absolute path of the module. |
| `build_id` | GNU build-id in lowercase hex, or `""`. Preferred join key. |
| `arch` | `"x86_64"` for version 1. |
| `is_64bit` | `true` for x86-64. |
| `prunable` | `false` when the call graph is unreliable for this module. |
| `prune_reason` | Human-readable reason when `prunable` is `false`. |
| `functions` | Function table. Indices are positions in this array. |
| `edges` | `edges[i]` is the direct-call adjacency list for `functions[i]`. |
| `roots` | The generator's default root set. Advisory; consumers recompute. |

`prunable` is `false` when the module contains IFUNC targets or
`setcontext`/`swapcontext`, because direct-call reconstruction is not sound
there. `return_offsets` remain valid: `--return-mode=ret` still works, while
`--trace-depth` and `export --static` degrade or fail. Modules that cannot be
analyzed at all (unreadable code, wrong architecture, ...) are omitted from the
document; the generator warns, and the primary module is fatal.

`edges[i]` contains module-local indices. Self-edges are kept, so direct
recursion is visible. Repeated callees are deduplicated. Indirect calls,
PLT/external calls, IFUNC targets, and cross-module calls add no edge.

## Function

```json
{
  "name": "main",
  "linkage_name": "main",
  "low_pc": 4198400,
  "high_pc": 4198460,
  "file_offset": 4096,
  "has_code": true,
  "exported": false,
  "address_taken": false,
  "entry": false,
  "init": false,
  "return_offsets": [4123, 4150]
}
```

| Field | Meaning |
|---|---|
| `name` | Demangled display name. May be empty. |
| `linkage_name` | Mangled symbol name. |
| `low_pc` / `high_pc` | Virtual address range. `low_pc` is the join key. |
| `file_offset` | File offset of the function entry. |
| `has_code` | `high_pc > low_pc`; the body was readable. |
| `exported` | Defined in `.dynsym` with global or weak binding. |
| `address_taken` | An operand or relocation materialises this address. |
| `entry` | The ELF entry point resolves here. |
| `init` | Listed in `.init_array` or `.fini_array`. |
| `return_offsets` | File offsets of `ret` instructions, ascending, unique. |

All numbers are JSON integers. Addresses and offsets are unsigned 64-bit for
x86-64 and fit comfortably in a JSON number.

## Root selection

`roots` is what the generator would use. The tracer recomputes roots from the
flags so that the policy lives in one program:

1. ELF entry (`entry`)
2. init/fini array entries (`init`)
3. exported symbols (`exported`)
4. address-taken functions (`address_taken`)
5. `main`

`main` sorts first; everything else ascends by `low_pc`. `--root-scope` and
`--regex` replace this set per module. A module with no matching root is
skipped; in single-module output it is an error.

## Joining facts to a running process

The tracer resolves a module with `ElfResolver` and matches it to a facts
module in this order:

1. non-empty `build_id` equal to the local build-id,
2. `path` equal after canonicalisation,
3. otherwise no match.

Within a matched module, functions are joined by `low_pc`. Facts whose
`low_pc` is not present locally are dropped; local functions without facts
simply have no edges. With `--return-mode=ret`, a module with no matched
functions or no return offsets is a hard error for the primary module, and a
warning plus skip for a module discovered later.

## Validation

A reader must reject the document when:

- `format` is missing or different
- `version` is missing or unknown
- `edges` and `functions` have different lengths
- any edge index is out of range

Out-of-range `roots` are dropped silently, because they are advisory.

## Size

Facts for a large closure such as libc are big because every function and every
direct edge is spelled out. `--root-scope` at generation time is not supported;
use `--root-scope` on the consumer for rendering, and expect the facts file
itself to stay large. `callgraph-disasm` always emits return offsets; there is
no switch to shrink the file at the cost of `ret` mode.

## Licensing

`callgraph-disasm` links libopcodes and is GPL-3.0-only. The facts file it
writes is data, not code; it carries no license of its own. The tracers read
the format without linking the generator.
