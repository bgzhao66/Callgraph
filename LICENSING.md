# Licensing

The repository produces three artifacts with three different licenses.

| Artifact | Source | License |
|---|---|---|
| `callgraph` | `src/`, `include/` (except the files listed below) | AGPL-3.0-only, or a commercial license |
| `callgraph-disasm` | `tools/disasm/`, `src/static_disasm.cpp` | GPL-3.0-only |
| `callgraph.sh` | `callgraph.sh` | MIT |

## `callgraph` — dual license

`callgraph` is available under either of two licenses, at your choice:

1. **AGPL-3.0-only.** The source in this repository is public. If you
   distribute the binary, or run a modified version as a network service, the
   AGPL's source-availability terms apply.
2. **Commercial license.** A separate agreement grants the right to use,
   modify, and distribute `callgraph` without the AGPL's source-availability
   obligations. Contact the maintainers for terms.

This is the standard dual-license model: the public license is the default, and
a commercial license removes its obligations for paying customers. There is no
free-as-in-beer binary edition; the same `callgraph` binary is used by both
licensees.

Because the project accepts outside contributions into the dual-licensed
artifact, contributors must grant the maintainers the right to relicense their
contribution. See `CLA.md`.

## `callgraph-disasm` — GPL-3.0-only

`callgraph-disasm` links `libopcodes`, which is GPL-3.0-or-later. Distributing
the binary therefore requires the complete corresponding source under the GPL.
The generator is kept deliberately small and self-contained; the tracer does
not link libopcodes or libbfd and contains no GPL code.

`callgraph-disasm` must remain a standalone program. Do not move code from it
into a shared library or a single combined executable, and do not make
`callgraph` link it: that would extend the GPL to the tracer.

## `callgraph.sh` — MIT

The wrapper contains no analysis logic, links nothing, and embeds no GPL code.
It parses arguments, runs `callgraph-disasm`, and `exec`s `callgraph`. It is
MIT-licensed so it can be redistributed freely alongside either edition of the
tracer.

## File map

| Path | License |
|---|---|
| `src/*.cpp`, `include/callgraph/*.h` | AGPL-3.0-only (unless listed below) |
| `bpf/*.bpf.c`, `bpf/**/*.bpf.h` | AGPL-3.0-only (the `"GPL"` in `SEC("license")` is a kernel-verifier requirement, not the distribution license) |
| `src/static_disasm.cpp`, `tools/disasm/main.cpp` | GPL-3.0-only |
| `callgraph.sh` | MIT |
| `tests/`, `docs/`, `cmake/`, `tools/install-deps.sh` | AGPL-3.0-only |
| `examples/` | AGPL-3.0-only |
| `third_party/libbpf` (submodule) | LGPL-2.1 OR BSD-2-Clause |
| `third_party/opentelemetry-proto` | Apache-2.0 |
| `tools/legacy/` | AGPL-3.0-only; not built |

## Third-party notices

The following libraries are linked, statically or dynamically, and their
licenses apply to the combined binaries:

| Library | License | Linked by |
|---|---|---|
| libbpf (vendored, static) | LGPL-2.1 OR BSD-2-Clause | both |
| elfutils `libelf`, `libdw` | LGPL-3.0-or-later OR GPL-2.0-or-later | both |
| libopcodes / libbfd | GPL-3.0-or-later | `callgraph-disasm` only |
| protobuf | BSD-3-Clause | `callgraph` when found |
| opentelemetry-proto | Apache-2.0 | `callgraph` when protobuf is found |
| libcurl | curl license (MIT-like) | `callgraph` when found |
| zlib | zlib license | both |

## Required repository files

The canonical license texts are not reproduced here. Before the first public
release, add:

- `COPYING` — the GNU Affero General Public License, version 3
- `COPYING.GPL-3.0` — the GNU General Public License, version 3
- `LICENSE.MIT` — the MIT license, matching the header in `callgraph.sh`
- `CLA.md` — the contributor license agreement
- `THIRD_PARTY_NOTICES` — the table above, with full texts

New source files should start with an SPDX identifier:

```
// SPDX-License-Identifier: AGPL-3.0-only
```

for `callgraph`, `// SPDX-License-Identifier: GPL-3.0-only` for
`callgraph-disasm`, and `# SPDX-License-Identifier: MIT` for the wrapper.
