#include "callgraph/argument_info.h"

#include <algorithm>
#include <cinttypes>
#include <cstdio>
#include <cstring>
#include <string>

#include "callgraph/event.h"

namespace callgraph {
namespace {

constexpr uint32_t kMaxGp = CG_MAX_GP_ARGS;
constexpr uint32_t kMaxSse = 8;
constexpr uint32_t kMaxStackBytes = CG_MAX_STACK_ARGS * 8;
constexpr uint32_t kMaxAggregateBytes = 16;

uint32_t align8(uint32_t value)
{
    return (value + 7u) & ~7u;
}

uint32_t slot_count(uint32_t byte_size)
{
    if (byte_size == 0)
        return 1;
    return std::max(1u, (byte_size + 7u) / 8u);
}

void clear_placement(ParameterInfo& parameter)
{
    parameter.in_sse = false;
    parameter.on_stack = false;
    parameter.unavailable = false;
    parameter.gp_index = 0xff;
    parameter.sse_index = 0xff;
    parameter.stack_offset = 0;
}

std::string hex_value(uint64_t value)
{
    char buffer[32];
    snprintf(buffer, sizeof(buffer), "0x%" PRIx64, value);
    return buffer;
}

std::string char_value(uint64_t value)
{
    const unsigned char c = static_cast<unsigned char>(value & 0xff);
    switch (c) {
    case '\\':
        return "'\\\\'";
    case '\'':
        return "'\\''";
    default:
        break;
    }

    if (c >= 0x20 && c < 0x7f) {
        char buffer[4] = {'\'', static_cast<char>(c), '\'', '\0'};
        return buffer;
    }

    char buffer[16];
    snprintf(buffer, sizeof(buffer), "0x%02x", c);
    return buffer;
}

uint64_t read_word(const cg_event& event, const ParameterInfo& parameter,
                   uint32_t index)
{
    if (parameter.gp_index != 0xff) {
        const uint32_t slot = parameter.gp_index + index;
        if (slot < CG_MAX_GP_ARGS)
            return event.args[slot];
        return 0;
    }

    if (parameter.on_stack) {
        const uint32_t slot = parameter.stack_offset / 8 + index;
        if (slot < CG_MAX_STACK_ARGS)
            return event.stack[slot];
        return 0;
    }

    return 0;
}

std::string format_aggregate(const ParameterInfo& parameter,
                             const cg_event& event)
{
    if (parameter.unavailable)
        return "?";

    const uint32_t slots = slot_count(parameter.byte_size);
    const uint32_t shown = std::min(slots, 4u);

    std::string out = "{";
    for (uint32_t i = 0; i < shown; ++i) {
        if (i != 0)
            out += ", ";
        out += hex_value(read_word(event, parameter, i));
    }
    if (slots > shown)
        out += ", ...";
    out += "}";
    return out;
}

std::string format_scalar(const ParameterInfo& parameter, uint64_t word,
                          const cg_event& event)
{
    switch (parameter.kind) {
    case ArgumentKind::Pointer:
        return hex_value(word);

    case ArgumentKind::Boolean: {
        uint64_t raw = word;
        if (parameter.byte_size > 0 && parameter.byte_size < 8)
            raw &= (1ULL << (parameter.byte_size * 8)) - 1;
        return raw != 0 ? "true" : "false";
    }

    case ArgumentKind::Char:
        return char_value(word);

    case ArgumentKind::Integer: {
        uint64_t raw = word;
        if (parameter.byte_size > 0 && parameter.byte_size < 8) {
            const uint32_t bits = parameter.byte_size * 8;
            const uint64_t mask = (1ULL << bits) - 1;
            raw &= mask;
            if (parameter.is_signed && (raw & (1ULL << (bits - 1))))
                raw |= ~mask;
        }
        if (parameter.is_signed)
            return std::to_string(static_cast<int64_t>(raw));
        return std::to_string(raw);
    }

    case ArgumentKind::Unsigned:
        if (parameter.byte_size > 0 && parameter.byte_size < 8)
            word &= (1ULL << (parameter.byte_size * 8)) - 1;
        return std::to_string(word);

    case ArgumentKind::Float: {
        if (parameter.in_sse || parameter.unavailable)
            return "?";
        if (parameter.byte_size == 4) {
            const uint32_t bits = static_cast<uint32_t>(word);
            float value = 0;
            memcpy(&value, &bits, sizeof(value));
            char buffer[32];
            snprintf(buffer, sizeof(buffer), "%g", value);
            return buffer;
        }
        if (parameter.byte_size == 8) {
            double value = 0;
            memcpy(&value, &word, sizeof(value));
            char buffer[32];
            snprintf(buffer, sizeof(buffer), "%g", value);
            return buffer;
        }
        return "?";
    }

    case ArgumentKind::Aggregate:
        return format_aggregate(parameter, event);

    case ArgumentKind::Unknown:
        if (parameter.byte_size > 8)
            return format_aggregate(parameter, event);
        return hex_value(word);
    }

    return hex_value(word);
}

}  // namespace

void classify_parameters(FunctionSignature& signature)
{
    uint32_t gp = 0;
    uint32_t sse = 0;
    uint32_t stack = 0;

    for (auto& parameter : signature.parameters) {
        clear_placement(parameter);

        const uint32_t size = parameter.byte_size == 0 ? 8 : parameter.byte_size;
        const uint32_t slots = slot_count(size);

        if (parameter.kind == ArgumentKind::Float) {
            // XMM registers are not part of struct pt_regs, so floating-point
            // values in registers can be located but not decoded.  Values
            // spilled to the stack can still be read from the captured bytes.
            if (size <= 8 && sse < kMaxSse) {
                parameter.in_sse = true;
                parameter.sse_index = static_cast<uint8_t>(sse);
                sse += 1;
                parameter.unavailable = true;
            } else {
                parameter.on_stack = true;
                parameter.stack_offset = stack;
                stack += align8(size);
            }
        } else if (parameter.kind == ArgumentKind::Aggregate &&
                   size <= kMaxAggregateBytes && !parameter.contains_float &&
                   gp + slots <= kMaxGp) {
            parameter.gp_index = static_cast<uint8_t>(gp);
            gp += slots;
        } else if (parameter.kind == ArgumentKind::Aggregate &&
                   size <= kMaxAggregateBytes && parameter.contains_float &&
                   sse + slots <= kMaxSse) {
            parameter.in_sse = true;
            parameter.sse_index = static_cast<uint8_t>(sse);
            sse += slots;
            parameter.unavailable = true;
        } else if (slots > 1 && !parameter.contains_float &&
                   parameter.kind != ArgumentKind::Float &&
                   gp + slots <= kMaxGp) {
            // Wide scalars such as __int128 consume multiple GP registers.
            parameter.gp_index = static_cast<uint8_t>(gp);
            gp += slots;
        } else if (slots == 1 && gp < kMaxGp) {
            parameter.gp_index = static_cast<uint8_t>(gp);
            gp += 1;
        } else {
            parameter.on_stack = true;
            parameter.stack_offset = stack;
            stack += align8(size);
        }

        if (parameter.on_stack &&
            parameter.stack_offset + size > kMaxStackBytes)
            parameter.unavailable = true;
    }
}

std::string format_arguments(const FunctionSignature& signature,
                             const cg_event& event)
{
    if (!signature.has_signature || signature.parameters.empty())
        return {};

    std::string out = " [";
    bool first = true;
    size_t unnamed = 0;

    for (const auto& parameter : signature.parameters) {
        if (parameter.artificial)
            continue;

        if (!first)
            out += ", ";
        first = false;

        if (parameter.name.empty()) {
            out += "arg";
            out += std::to_string(unnamed);
        } else {
            out += parameter.name;
        }
        ++unnamed;

        out += '=';
        if (parameter.unavailable || parameter.in_sse ||
            (parameter.gp_index == 0xff && !parameter.on_stack)) {
            out += '?';
        } else {
            out += format_scalar(parameter, read_word(event, parameter, 0),
                                 event);
        }
    }

    if (first)
        return {};

    out += ']';
    return out;
}

}  // namespace callgraph
