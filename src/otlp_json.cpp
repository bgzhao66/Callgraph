#include "callgraph/otlp_json.h"

#include <cstdio>
#include <string>

namespace callgraph {
namespace {

void append_escaped(std::string& out, const std::string& value)
{
    out.push_back('"');
    for (unsigned char c : value) {
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
                std::snprintf(buffer, sizeof(buffer), "\\u%04x", c);
                out += buffer;
            } else {
                out.push_back(static_cast<char>(c));
            }
            break;
        }
    }
    out.push_back('"');
}

void append_key(std::string& out, const char* key)
{
    append_escaped(out, key);
    out += ':';
}

void append_string_attr(std::string& out, const char* key,
                        const std::string& value, bool* first)
{
    if (!*first)
        out.push_back(',');
    *first = false;
    out += '{';
    append_key(out, "key");
    append_escaped(out, key);
    out += ',';
    append_key(out, "value");
    out += '{';
    append_key(out, "stringValue");
    append_escaped(out, value);
    out += "}}";
}

void append_int_attr(std::string& out, const char* key, uint64_t value,
                     bool* first)
{
    if (!*first)
        out.push_back(',');
    *first = false;
    out += '{';
    append_key(out, "key");
    append_escaped(out, key);
    out += ',';
    append_key(out, "value");
    out += '{';
    append_key(out, "intValue");
    out.push_back('"');
    out += std::to_string(value);
    out += "\"}}";
}

void append_bool_attr(std::string& out, const char* key, bool value,
                      bool* first)
{
    if (!*first)
        out.push_back(',');
    *first = false;
    out += '{';
    append_key(out, "key");
    append_escaped(out, key);
    out += ',';
    append_key(out, "value");
    out += '{';
    append_key(out, "boolValue");
    out += value ? "true" : "false";
    out += "}}";
}

std::string hex_bytes(const uint8_t* data, size_t size)
{
    static const char* digits = "0123456789abcdef";
    std::string out;
    out.resize(size * 2);
    for (size_t i = 0; i < size; ++i) {
        out[i * 2] = digits[data[i] >> 4];
        out[i * 2 + 1] = digits[data[i] & 0x0f];
    }
    return out;
}

std::string trace_id_hex(const TraceId& id)
{
    return hex_bytes(id.data(), id.size());
}

std::string span_id_hex(uint64_t id)
{
    uint8_t bytes[8];
    for (int i = 7; i >= 0; --i) {
        bytes[i] = static_cast<uint8_t>(id & 0xff);
        id >>= 8;
    }
    return hex_bytes(bytes, sizeof(bytes));
}

std::string basename_of(const std::string& path)
{
    const size_t slash = path.find_last_of('/');
    return slash == std::string::npos ? path : path.substr(slash + 1);
}

void append_span(std::string& out, const SpanRecord& span,
                 const OtelConfig& config)
{
    out += '{';
    append_key(out, "traceId");
    append_escaped(out, trace_id_hex(span.context.trace_id));
    out += ',';
    append_key(out, "spanId");
    append_escaped(out, span_id_hex(span.context.span_id));

    if (span.context.parent_span_id != 0) {
        out += ',';
        append_key(out, "parentSpanId");
        append_escaped(out, span_id_hex(span.context.parent_span_id));
    }

    out += ',';
    append_key(out, "name");
    append_escaped(out, span.function.name);
    out += ',';
    append_key(out, "kind");
    out += '1';  // SPAN_KIND_INTERNAL
    out += ',';
    append_key(out, "startTimeUnixNano");
    out.push_back('"');
    out += std::to_string(span.start_unix_ns);
    out += "\",";
    append_key(out, "endTimeUnixNano");
    out.push_back('"');
    out += std::to_string(span.end_unix_ns);
    out += "\"";

    out += ',';
    append_key(out, "attributes");
    out.push_back('[');
    bool first = true;

    append_string_attr(out, "code.function.name", span.function.name, &first);
    append_string_attr(out, "code.function", span.function.name, &first);
    if (!span.function.source_file.empty()) {
        append_string_attr(out, "code.filepath", span.function.source_file,
                           &first);
        if (span.function.source_line != 0) {
            append_int_attr(out, "code.lineno", span.function.source_line,
                            &first);
        }
    }
    if (!span.function.linkage_name.empty())
        append_string_attr(out, "callgraph.linkage_name",
                           span.function.linkage_name, &first);
    append_int_attr(out, "callgraph.function_id", span.function_id, &first);
    append_int_attr(out, "callgraph.depth", span.depth, &first);
    append_int_attr(out, "thread.id", span.tid, &first);
    if (!span.thread_name.empty())
        append_string_attr(out, "thread.name", span.thread_name, &first);
    append_bool_attr(out, "callgraph.root",
                     span.context.parent_span_id == 0, &first);
    if (config.attach_mode && span.context.parent_span_id == 0)
        append_bool_attr(out, "callgraph.partial_stack", true, &first);
    if (!span.function.module_path.empty()) {
        append_string_attr(out, "callgraph.module",
                           basename_of(span.function.module_path), &first);
        append_string_attr(out, "callgraph.module.path",
                           span.function.module_path, &first);
    }
    if (!span.function.module_build_id.empty()) {
        append_string_attr(out, "callgraph.module.build_id",
                           span.function.module_build_id, &first);
    }
    if (span.function.file_offset != 0) {
        append_int_attr(out, "callgraph.file_offset",
                        span.function.file_offset, &first);
    }
    if (!span.arguments.empty())
        append_string_attr(out, "callgraph.arguments", span.arguments, &first);
    if (span.incomplete) {
        append_bool_attr(out, "callgraph.incomplete", true, &first);
        append_string_attr(out, "callgraph.end_reason",
                           span_close_reason_name(span.reason), &first);
    }

    out += "]}";
}

void append_resource(std::string& out, const OtelConfig& config)
{
    append_key(out, "resource");
    out += '{';
    append_key(out, "attributes");
    out.push_back('[');
    bool first = true;

    const std::string service =
        config.service_name.empty() ? "unknown_service" : config.service_name;
    append_string_attr(out, "service.name", service, &first);
    if (!config.service_namespace.empty())
        append_string_attr(out, "service.namespace", config.service_namespace,
                           &first);
    if (!config.service_instance_id.empty())
        append_string_attr(out, "service.instance.id",
                           config.service_instance_id, &first);
    append_string_attr(out, "telemetry.sdk.name", "callgraph", &first);
    append_string_attr(out, "telemetry.sdk.language", "cpp", &first);
    if (!config.tool_version.empty())
        append_string_attr(out, "telemetry.sdk.version", config.tool_version,
                           &first);
    if (config.pid > 0)
        append_int_attr(out, "process.pid", static_cast<uint64_t>(config.pid),
                        &first);
    if (!config.executable_name.empty())
        append_string_attr(out, "process.executable.name",
                           config.executable_name, &first);
    if (!config.executable_path.empty())
        append_string_attr(out, "process.executable.path",
                           config.executable_path, &first);
    if (!config.command_line.empty())
        append_string_attr(out, "process.command_line", config.command_line,
                           &first);
    if (!config.host_name.empty())
        append_string_attr(out, "host.name", config.host_name, &first);
    if (!config.host_arch.empty())
        append_string_attr(out, "host.arch", config.host_arch, &first);
    append_string_attr(out, "os.type", "linux", &first);
    if (!config.os_description.empty())
        append_string_attr(out, "os.description", config.os_description,
                           &first);
    if (!config.return_mode.empty())
        append_string_attr(out, "callgraph.return_mode", config.return_mode,
                           &first);
    if (!config.trace_scope.empty())
        append_string_attr(out, "callgraph.trace_scope", config.trace_scope,
                           &first);
    append_bool_attr(out, "callgraph.attach_mode", config.attach_mode, &first);
    append_int_attr(out, "callgraph.monotonic_offset_ns",
                    config.monotonic_offset_ns, &first);
    if (!config.tool_version.empty())
        append_string_attr(out, "callgraph.version", config.tool_version,
                           &first);

    out += "]}";
}

}  // namespace

std::string encode_otlp_request(const std::vector<SpanRecord>& spans,
                                const OtelConfig& config)
{
    std::string out;
    out.reserve(1024 + spans.size() * 512);
    out += '{';
    append_key(out, "resourceSpans");
    out += '[';
    out += '{';
    append_resource(out, config);
    out += ',';
    append_key(out, "scopeSpans");
    out += '[';
    out += '{';
    append_key(out, "scope");
    out += '{';
    append_key(out, "name");
    append_escaped(out, "callgraph");
    out += ',';
    append_key(out, "version");
    append_escaped(out, config.tool_version.empty() ? "0.1.0"
                                                    : config.tool_version);
    out += '}';
    out += ',';
    append_key(out, "spans");
    out += '[';
    for (size_t i = 0; i < spans.size(); ++i) {
        if (i != 0)
            out.push_back(',');
        append_span(out, spans[i], config);
    }
    out += ']';
    out += '}';  // scopeSpans entry
    out += ']';  // scopeSpans array
    out += '}';  // resourceSpans entry
    out += ']';  // resourceSpans array
    out += '}';
    return out;
}

}  // namespace callgraph
