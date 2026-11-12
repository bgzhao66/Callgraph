#pragma once

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <sys/types.h>
#include <vector>

#include "callgraph/span.h"

namespace callgraph {

enum class OtlpProtocol {
    JsonHttp,
    ProtobufHttp,
    Grpc,
};

struct OtelConfig {
    std::string output_path;
    std::string endpoint;
    OtlpProtocol protocol = OtlpProtocol::JsonHttp;
    std::vector<std::string> headers;

    std::string service_name;
    std::string service_namespace;
    std::string service_instance_id;
    std::string executable_name;
    std::string executable_path;
    std::string command_line;
    pid_t pid = 0;
    std::string return_mode;
    std::string trace_scope;
    std::string tool_version;
    std::string host_name;
    std::string host_arch;
    std::string os_description;
    bool attach_mode = false;
    uint64_t monotonic_offset_ns = 0;

    size_t batch_spans = 512;
    size_t batch_bytes = 1 << 20;
    int flush_ms = 1000;
    int timeout_ms = 5000;
    size_t queue_spans = 10000;
    bool gzip = false;
};

class OtelExporter {
public:
    explicit OtelExporter(OtelConfig config);
    ~OtelExporter();

    OtelExporter(const OtelExporter&) = delete;
    OtelExporter& operator=(const OtelExporter&) = delete;

    void export_span(SpanRecord&& span);
    void finish();

    uint64_t exported() const { return exported_.load(std::memory_order_relaxed); }
    uint64_t dropped() const { return dropped_.load(std::memory_order_relaxed); }
    uint64_t failed() const { return failed_.load(std::memory_order_relaxed); }
    bool has_endpoint() const { return !config_.endpoint.empty(); }
    bool has_output() const { return !config_.output_path.empty(); }

private:
    void write_file();

    OtelConfig config_;
    std::vector<SpanRecord> file_spans_;

    struct HttpWorker;
    std::unique_ptr<HttpWorker> http_;

    std::atomic<uint64_t> exported_{0};
    std::atomic<uint64_t> dropped_{0};
    std::atomic<uint64_t> failed_{0};
    bool finished_ = false;
};

bool otlp_http_available();

}  // namespace callgraph
