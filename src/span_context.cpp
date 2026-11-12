#include "callgraph/span_context.h"

#include <random>

namespace callgraph {
namespace {

uint64_t splitmix64(uint64_t value)
{
    value += 0x9e3779b97f4a7c15ULL;
    value = (value ^ (value >> 30)) * 0xbf58476d1ce4e5b9ULL;
    value = (value ^ (value >> 27)) * 0x94d049bb133111ebULL;
    return value ^ (value >> 31);
}

void store_be64(uint8_t* out, uint64_t value)
{
    for (int i = 7; i >= 0; --i) {
        out[i] = static_cast<uint8_t>(value & 0xff);
        value >>= 8;
    }
}

bool trace_id_is_zero(const TraceId& id)
{
    for (uint8_t byte : id) {
        if (byte != 0)
            return false;
    }
    return true;
}

}  // namespace

SpanContextManager::SpanContextManager(uint64_t seed_hi, uint64_t seed_lo)
    : seed_hi_(seed_hi), seed_lo_(seed_lo)
{
}

TraceId SpanContextManager::new_trace(uint32_t tid, uint64_t sequence)
{
    const uint64_t mixed_tid =
        (static_cast<uint64_t>(tid) << 32) ^ static_cast<uint64_t>(tid);
    const uint64_t a = splitmix64(seed_hi_ ^ mixed_tid ^
                                  (sequence * 0x9e3779b97f4a7c15ULL));
    const uint64_t b = splitmix64(seed_lo_ ^ a ^
                                  (sequence * 0xc2b2ae3d27d4eb4fULL) ^
                                  0xd1b54a32d192ed03ULL);

    TraceId id{};
    store_be64(id.data(), a);
    store_be64(id.data() + 8, b);
    if (trace_id_is_zero(id))
        id[15] = 1;
    return id;
}

uint64_t SpanContextManager::next_span_id()
{
    // A monotonic token is unique across all traces in this session, which is
    // stronger than the OTLP requirement of uniqueness within one trace.
    return next_span_id_++;
}

void random_seed(uint64_t* hi, uint64_t* lo)
{
    std::random_device device;
    uint64_t a = (static_cast<uint64_t>(device()) << 32) ^ device();
    uint64_t b = (static_cast<uint64_t>(device()) << 32) ^ device();
    *hi = splitmix64(a ^ 0x243f6a8885a308d3ULL);
    *lo = splitmix64(b ^ 0x13198a2e03707344ULL);
    if (*hi == 0 && *lo == 0)
        *lo = 1;
}

}  // namespace callgraph
