#pragma once

#include <cstdint>
#include <string>
#include <sys/types.h>
#include <unordered_map>
#include <vector>

#include "callgraph/span.h"

namespace callgraph {

struct TraceMetadata {
    bool present = false;
    std::string service_name;
    std::string service_namespace;
    std::string service_instance_id;
    pid_t pid = 0;
    uint64_t monotonic_offset_ns = 0;
    uint64_t seed_hi = 0;
    uint64_t seed_lo = 0;
    std::string return_mode;
    std::string trace_scope;
    bool attach_mode = false;
    std::vector<FunctionMetadata> functions;
};

bool write_trace_metadata(const std::string& path,
                          const TraceMetadata& metadata);

// Reads a sidecar written by write_trace_metadata().  Returns false when the
// file cannot be opened or is not a callgraph metadata file.
bool read_trace_metadata(const std::string& path, TraceMetadata* metadata);

// Builds a name -> metadata lookup for enriching an offline text trace.
std::unordered_map<std::string, FunctionMetadata>
metadata_by_name(const TraceMetadata& metadata);

}  // namespace callgraph
