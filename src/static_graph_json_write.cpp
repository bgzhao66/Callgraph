// SPDX-License-Identifier: GPL-3.0-only
#include "callgraph/static_graph_json.h"

#include <cstdio>
#include <string>

namespace callgraph {

namespace {

void append_escaped(std::string& out, const std::string& value)
{
    out.push_back('"');
    for (const char raw : value) {
        const unsigned char c = static_cast<unsigned char>(raw);
        switch (c) {
        case '"':
            out += "\\\"";
            break;
        case '\\':
            out += "\\\\";
            break;
        case '\b':
            out += "\\b";
            break;
        case '\f':
            out += "\\f";
            break;
        case '\n':
            out += "\\n";
            break;
        case '\r':
            out += "\\r";
            break;
        case '\t':
            out += "\\t";
            break;
        default:
            if (c < 0x20) {
                char buffer[8];
                snprintf(buffer, sizeof(buffer), "\\u%04x", c);
                out += buffer;
            } else {
                out.push_back(raw);
            }
            break;
        }
    }
    out.push_back('"');
}

void append_bool(std::string& out, bool value)
{
    out += value ? "true" : "false";
}

void append_offsets(std::string& out, const std::vector<uint64_t>& offsets)
{
    out.push_back('[');
    for (size_t i = 0; i < offsets.size(); ++i) {
        if (i != 0)
            out.push_back(',');
        out += std::to_string(offsets[i]);
    }
    out.push_back(']');
}

void append_indices(std::string& out, const std::vector<size_t>& indices)
{
    out.push_back('[');
    for (size_t i = 0; i < indices.size(); ++i) {
        if (i != 0)
            out.push_back(',');
        out += std::to_string(indices[i]);
    }
    out.push_back(']');
}

void append_function(std::string& out, const StaticGraphFunction& function)
{
    out += "{\"name\":";
    append_escaped(out, function.name);
    out += ",\"linkage_name\":";
    append_escaped(out, function.linkage_name);
    out += ",\"low_pc\":";
    out += std::to_string(function.low_pc);
    out += ",\"high_pc\":";
    out += std::to_string(function.high_pc);
    out += ",\"file_offset\":";
    out += std::to_string(function.file_offset);
    out += ",\"has_code\":";
    append_bool(out, function.has_code);
    out += ",\"exported\":";
    append_bool(out, function.exported);
    out += ",\"address_taken\":";
    append_bool(out, function.address_taken);
    out += ",\"entry\":";
    append_bool(out, function.entry);
    out += ",\"init\":";
    append_bool(out, function.init);
    out += ",\"return_offsets\":";
    append_offsets(out, function.return_offsets);
    out.push_back('}');
}

void append_module(std::string& out, const StaticGraphModule& module)
{
    out += "{\"path\":";
    append_escaped(out, module.path);
    out += ",\"build_id\":";
    append_escaped(out, module.build_id);
    out += ",\"arch\":";
    append_escaped(out, module.arch);
    out += ",\"is_64bit\":";
    append_bool(out, module.is_64bit);
    out += ",\"prunable\":";
    append_bool(out, module.prunable);
    out += ",\"prune_reason\":";
    append_escaped(out, module.prune_reason);

    out += ",\"functions\":[";
    for (size_t i = 0; i < module.functions.size(); ++i) {
        if (i != 0)
            out.push_back(',');
        append_function(out, module.functions[i]);
    }
    out.push_back(']');

    out += ",\"edges\":[";
    for (size_t i = 0; i < module.edges.size(); ++i) {
        if (i != 0)
            out.push_back(',');
        append_indices(out, module.edges[i]);
    }
    out.push_back(']');

    out += ",\"roots\":";
    append_indices(out, module.roots);
    out.push_back('}');
}

}  // namespace

std::string write_static_graph_json(const StaticGraphDocument& document)
{
    std::string out;
    out.reserve(1 << 16);
    out += "{\"format\":";
    append_escaped(out, kStaticGraphFormat);
    out += ",\"version\":";
    out += std::to_string(kStaticGraphFormatVersion);
    out += ",\"generator\":{\"name\":\"callgraph-disasm\",\"version\":";
#ifdef CALLGRAPH_VERSION
    append_escaped(out, CALLGRAPH_VERSION);
#else
    append_escaped(out, "unknown");
#endif
    out += "},\"modules\":[";
    for (size_t i = 0; i < document.modules.size(); ++i) {
        if (i != 0)
            out.push_back(',');
        append_module(out, document.modules[i]);
    }
    out += "]}";
    out.push_back('\n');
    return out;
}

}  // namespace callgraph
