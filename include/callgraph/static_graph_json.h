// SPDX-License-Identifier: AGPL-3.0-only
#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace callgraph {

// Version of the on-disk call-graph facts format.  Bump when a field changes
// meaning or is removed; readers must reject unknown versions.
constexpr int kStaticGraphFormatVersion = 1;
inline constexpr char kStaticGraphFormat[] = "callgraph-static-graph";

struct StaticGraphFunction {
    std::string name;
    std::string linkage_name;
    uint64_t low_pc = 0;
    uint64_t high_pc = 0;
    uint64_t file_offset = 0;
    bool has_code = false;
    bool exported = false;
    bool address_taken = false;
    bool entry = false;
    bool init = false;
    std::vector<uint64_t> return_offsets;
};

struct StaticGraphModule {
    std::string path;
    std::string build_id;
    std::string arch;
    bool is_64bit = false;
    // False when the call graph is unreliable for this module (IFUNC targets
    // or stackful context switches).  Return offsets remain valid.
    bool prunable = true;
    std::string prune_reason;
    // Indexed by position; `edges` and `roots` refer to these indices.
    std::vector<StaticGraphFunction> functions;
    std::vector<std::vector<size_t>> edges;
    // Default roots computed by the generator.  Advisory: consumers may
    // recompute them from the per-function flags.
    std::vector<size_t> roots;
};

struct StaticGraphDocument {
    std::vector<StaticGraphModule> modules;
};

// Serialises `document` as compact JSON.
std::string write_static_graph_json(const StaticGraphDocument& document);

// Parses and validates facts.  Returns false and fills `reason` on malformed
// input or an unsupported version.
bool read_static_graph_json(const std::string& text,
                            StaticGraphDocument* document, std::string* reason);

}  // namespace callgraph
