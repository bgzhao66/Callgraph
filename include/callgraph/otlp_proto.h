#pragma once

#include <string>
#include <vector>

#include "callgraph/otel_exporter.h"
#include "callgraph/span.h"

namespace callgraph {

bool otlp_protobuf_available();

// Encodes an OTLP ExportTraceServiceRequest using the generated OTLP protobuf
// messages.  Returns an empty string when protobuf support was not compiled.
std::string encode_otlp_protobuf(const std::vector<SpanRecord>& spans,
                                 const OtelConfig& config);

}  // namespace callgraph
