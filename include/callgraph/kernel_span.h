#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "callgraph/span.h"

namespace callgraph {

// A TID-attributed kernel interval starts here.  The sink returns an opaque
// token that must be passed back to on_kernel_exit.
struct KernelSpanStart {
    uint64_t parent_token = 0;
    uint32_t tid = 0;
    uint32_t user_depth = 0;
    uint8_t category = 0;
    std::string name;
    uint64_t ts = 0;
    std::vector<SpanAttribute> attributes;
};

struct KernelSpanEnd {
    uint64_t ts = 0;
    std::vector<SpanAttribute> attributes;
    bool incomplete = false;
};

// A zero-duration TID-attributed kernel event.
struct KernelSpanPoint {
    uint64_t parent_token = 0;
    uint32_t tid = 0;
    uint32_t user_depth = 0;
    uint8_t category = 0;
    std::string name;
    uint64_t ts = 0;
    std::vector<SpanAttribute> attributes;
};

// Receives kernel spans from KernelTimeline.  Implementations must not block.
class KernelSpanSink {
public:
    virtual ~KernelSpanSink() = default;

    virtual uint64_t on_kernel_enter(KernelSpanStart&& start) = 0;
    virtual void on_kernel_exit(uint64_t token, KernelSpanEnd&& end) = 0;
    virtual void on_kernel_point(KernelSpanPoint&& point) = 0;
};

}  // namespace callgraph
