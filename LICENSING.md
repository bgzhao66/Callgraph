# Licensing

The repository produces five artifacts with three different licenses.

| Artifact | Source | License |
|---|---|---|
| `callgraph-run` | `src/main_run.cpp` + shared core/trace | AGPL-3.0-only, or a commercial license |
| `callgraph-attach` | `src/main_attach.cpp` + shared core/trace | AGPL-3.0-only, or a commercial license |
| `callgraph-export` | `src/main_export.cpp` + shared core | AGPL-3.0-only, or a commercial license |
| `callgraph-disasm` | `tools/disasm/`, `src/static_disasm.cpp` | GPL-3.0-only |
| `callgraph.sh` | `callgraph.sh` | MIT |

## `callgraph-run`, `callgraph-attach`, `callgraph-export` — dual license

The three tracer/exporter programs are available under either of two
licenses, at your choice:

1. **AGPL-3.0-only.** The source in this repository is public. If you
   distribute any of the binaries, or run a modified version as a network
   service, the AGPL's source-availability terms apply.
2. **Commercial license.** A separate agreement grants the right to use,
   modify, and distribute the programs without the AGPL's source-availability
   obligations. Contact the maintainers for terms.

This is the standard dual-license model: the public license is the default, and
a commercial license removes its obligations for paying customers. There is no
free-as-in-beer binary edition; the same binaries are used by both
licensees.

Because the project accepts outside contributions into the dual-licensed
artifact, contributors must grant the maintainers the right to relicense their
contribution. See `CLA.md`.

## `callgraph-disasm` — GPL-3.0-only

`callgraph-disasm` links `libopcodes`, which is GPL-3.0-or-later. Distributing
the binary therefore requires the complete corresponding source under the GPL.
The generator is kept deliberately small and self-contained; the tracer
programs do not link libopcodes or libbfd and contain no GPL code.

`callgraph-disasm` must remain a standalone program. Do not move code from it
into a shared library or a single combined executable, and do not make
`callgraph-run`/`callgraph-attach`/`callgraph-export` link it: that would
extend the GPL to the tracers.

## `callgraph.sh` — MIT

The wrapper contains no analysis logic, links nothing, and embeds no GPL code.
It parses arguments, runs `callgraph-disasm`, and `exec`s the matching tracer
or exporter program. It is MIT-licensed so it can be redistributed freely
alongside either edition.

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
| libbpf (vendored, static) | LGPL-2.1 OR BSD-2-Clause | `callgraph-run`, `callgraph-attach` |
| elfutils `libelf`, `libdw` | LGPL-3.0-or-later OR GPL-2.0-or-later | run, attach (and libelf in export via the facts reader) |
| libopcodes / libbfd | GPL-3.0-or-later | `callgraph-disasm` only |
| protobuf | BSD-3-Clause | all three programs when found |
| opentelemetry-proto | Apache-2.0 | all three programs when protobuf is found |
| libcurl | curl license (MIT-like) | all three programs when found |
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

for the tracer programs, `// SPDX-License-Identifier: GPL-3.0-only` for
`callgraph-disasm`, and `# SPDX-License-Identifier: MIT` for the wrapper.
