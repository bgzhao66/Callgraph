#include "callgraph/otlp_proto.h"

#ifdef CALLGRAPH_HAVE_OTLP_PROTO

#include <cstdint>
#include <string>

#include "opentelemetry/proto/collector/trace/v1/trace_service.pb.h"
#include "opentelemetry/proto/common/v1/common.pb.h"
#include "opentelemetry/proto/resource/v1/resource.pb.h"
#include "opentelemetry/proto/trace/v1/trace.pb.h"

namespace callgraph {
namespace {

namespace common = opentelemetry::proto::common::v1;
namespace resource = opentelemetry::proto::resource::v1;
namespace trace = opentelemetry::proto::trace::v1;
namespace collector = opentelemetry::proto::collector::trace::v1;

using Attributes = google::protobuf::RepeatedPtrField<common::KeyValue>;

void add_string(Attributes* attributes, const char* key,
                const std::string& value)
{
    common::KeyValue* kv = attributes->Add();
    kv->set_key(key);
    kv->mutable_value()->set_string_value(value);
}

void add_int(Attributes* attributes, const char* key, int64_t value)
{
    common::KeyValue* kv = attributes->Add();
    kv->set_key(key);
    kv->mutable_value()->set_int_value(value);
}

void add_bool(Attributes* attributes, const char* key, bool value)
{
    common::KeyValue* kv = attributes->Add();
    kv->set_key(key);
    kv->mutable_value()->set_bool_value(value);
}

std::string basename_of(const std::string& path)
{
    const size_t slash = path.find_last_of('/');
    return slash == std::string::npos ? path : path.substr(slash + 1);
}

std::string trace_id_bytes(const TraceId& id)
{
    return std::string(reinterpret_cast<const char*>(id.data()), id.size());
}

std::string span_id_bytes(uint64_t id)
{
    uint8_t bytes[8];
    for (int i = 7; i >= 0; --i) {
        bytes[i] = static_cast<uint8_t>(id & 0xff);
        id >>= 8;
    }
    return std::string(reinterpret_cast<const char*>(bytes), sizeof(bytes));
}

void fill_resource(resource::Resource* out, const OtelConfig& config)
{
    Attributes* attributes = out->mutable_attributes();
    const std::string service =
        config.service_name.empty() ? "unknown_service" : config.service_name;
    add_string(attributes, "service.name", service);
    if (!config.service_namespace.empty())
        add_string(attributes, "service.namespace", config.service_namespace);
    if (!config.service_instance_id.empty())
        add_string(attributes, "service.instance.id",
                   config.service_instance_id);
    add_string(attributes, "telemetry.sdk.name", "callgraph");
    add_string(attributes, "telemetry.sdk.language", "cpp");
    if (!config.tool_version.empty())
        add_string(attributes, "telemetry.sdk.version", config.tool_version);
    if (config.pid > 0)
        add_int(attributes, "process.pid", config.pid);
    if (!config.executable_name.empty())
        add_string(attributes, "process.executable.name",
                   config.executable_name);
    if (!config.executable_path.empty())
        add_string(attributes, "process.executable.path",
                   config.executable_path);
    if (!config.command_line.empty())
        add_string(attributes, "process.command_line", config.command_line);
    if (!config.host_name.empty())
        add_string(attributes, "host.name", config.host_name);
    if (!config.host_arch.empty())
        add_string(attributes, "host.arch", config.host_arch);
    add_string(attributes, "os.type", "linux");
    if (!config.os_description.empty())
        add_string(attributes, "os.description", config.os_description);
    if (!config.return_mode.empty())
        add_string(attributes, "callgraph.return_mode", config.return_mode);
    if (!config.trace_scope.empty())
        add_string(attributes, "callgraph.trace_scope", config.trace_scope);
    add_bool(attributes, "callgraph.attach_mode", config.attach_mode);
    add_int(attributes, "callgraph.monotonic_offset_ns",
            static_cast<int64_t>(config.monotonic_offset_ns));
    if (!config.tool_version.empty())
        add_string(attributes, "callgraph.version", config.tool_version);
}

void fill_span(trace::Span* out, const SpanRecord& span,
               const OtelConfig& config)
{
    out->set_trace_id(trace_id_bytes(span.context.trace_id));
    out->set_span_id(span_id_bytes(span.context.span_id));
    if (span.context.parent_span_id != 0)
        out->set_parent_span_id(span_id_bytes(span.context.parent_span_id));
    out->set_name(span.function.name);
    out->set_kind(trace::Span::SPAN_KIND_INTERNAL);
    out->set_start_time_unix_nano(span.start_unix_ns);
    out->set_end_time_unix_nano(span.end_unix_ns);

    Attributes* attributes = out->mutable_attributes();
    add_string(attributes, "code.function.name", span.function.name);
    add_string(attributes, "code.function", span.function.name);
    if (!span.function.source_file.empty()) {
        add_string(attributes, "code.filepath", span.function.source_file);
        if (span.function.source_line != 0)
            add_int(attributes, "code.lineno", span.function.source_line);
    }
    if (!span.function.linkage_name.empty())
        add_string(attributes, "callgraph.linkage_name",
                   span.function.linkage_name);
    add_int(attributes, "callgraph.function_id", span.function_id);
    add_int(attributes, "callgraph.depth", span.depth);
    add_int(attributes, "thread.id", span.tid);
    if (!span.thread_name.empty())
        add_string(attributes, "thread.name", span.thread_name);
    add_bool(attributes, "callgraph.root", span.context.parent_span_id == 0);
    if (config.attach_mode && span.context.parent_span_id == 0)
        add_bool(attributes, "callgraph.partial_stack", true);
    if (!span.function.module_path.empty()) {
        add_string(attributes, "callgraph.module",
                   basename_of(span.function.module_path));
        add_string(attributes, "callgraph.module.path",
                   span.function.module_path);
    }
    if (!span.function.module_build_id.empty())
        add_string(attributes, "callgraph.module.build_id",
                   span.function.module_build_id);
    if (span.function.file_offset != 0)
        add_int(attributes, "callgraph.file_offset", span.function.file_offset);
    if (!span.arguments.empty())
        add_string(attributes, "callgraph.arguments", span.arguments);
    if (span.incomplete) {
        add_bool(attributes, "callgraph.incomplete", true);
        add_string(attributes, "callgraph.end_reason",
                   span_close_reason_name(span.reason));
    }
}

}  // namespace

bool otlp_protobuf_available()
{
    return true;
}

std::string encode_otlp_protobuf(const std::vector<SpanRecord>& spans,
                                 const OtelConfig& config)
{
    collector::ExportTraceServiceRequest request;
    auto* resource_spans = request.add_resource_spans();
    fill_resource(resource_spans->mutable_resource(), config);

    auto* scope_spans = resource_spans->add_scope_spans();
    scope_spans->mutable_scope()->set_name("callgraph");
    scope_spans->mutable_scope()->set_version(
        config.tool_version.empty() ? "0.1.0" : config.tool_version);

    for (const auto& span : spans)
        fill_span(scope_spans->add_spans(), span, config);

    return request.SerializeAsString();
}

}  // namespace callgraph

#else

namespace callgraph {

bool otlp_protobuf_available()
{
    return false;
}

std::string encode_otlp_protobuf(const std::vector<SpanRecord>&,
                                 const OtelConfig&)
{
    return {};
}

}  // namespace callgraph

#endif
