#pragma once

#include <string>
#include <vector>

#include "callgraph/otel_exporter.h"
#include "callgraph/span.h"

namespace callgraph {

// Encodes one OTLP/HTTP JSON ExportTraceServiceRequest body.  The vector may
// be a batch; resource and scope metadata are shared by all spans.
std::string encode_otlp_request(const std::vector<SpanRecord>& spans,
                                const OtelConfig& config);

}  // namespace callgraph
