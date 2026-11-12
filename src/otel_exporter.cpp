#include "callgraph/otel_exporter.h"

#include <cerrno>
#include <cctype>
#include <chrono>
#include <condition_variable>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <mutex>
#include <thread>
#include <utility>

#include "callgraph/common.h"
#include "callgraph/otlp_json.h"
#include "callgraph/otlp_proto.h"

#ifdef CALLGRAPH_HAVE_CURL
#include <curl/curl.h>
#endif

#ifdef CALLGRAPH_HAVE_CURL
#include <zlib.h>
#endif

namespace callgraph {
namespace {

size_t span_cost(const SpanRecord& span)
{
    return 256 + span.function.name.size() + span.function.linkage_name.size() +
           span.function.module_path.size() +
           span.function.module_build_id.size() + span.arguments.size();
}

std::string grpc_body(const std::string& payload)
{
    std::string body;
    body.reserve(payload.size() + 5);
    body.push_back('\0');
    const uint32_t size = static_cast<uint32_t>(payload.size());
    body.push_back(static_cast<char>((size >> 24) & 0xff));
    body.push_back(static_cast<char>((size >> 16) & 0xff));
    body.push_back(static_cast<char>((size >> 8) & 0xff));
    body.push_back(static_cast<char>(size & 0xff));
    body.append(payload);
    return body;
}

std::string grpc_endpoint(std::string endpoint)
{
    if (endpoint.find("://") == std::string::npos)
        endpoint = "http://" + endpoint;
    const size_t scheme = endpoint.find("://");
    const size_t path = endpoint.find('/', scheme + 3);
    if (path == std::string::npos)
        endpoint += "/opentelemetry.proto.collector.trace.v1.TraceService/Export";
    else if (path + 1 == endpoint.size())
        endpoint += "opentelemetry.proto.collector.trace.v1.TraceService/Export";
    return endpoint;
}

#ifdef CALLGRAPH_HAVE_CURL
struct GrpcHeaderState {
    bool saw_status = false;
    long status = -1;
};

size_t grpc_header_callback(char* buffer, size_t size, size_t count,
                            void* userdata)
{
    auto* state = static_cast<GrpcHeaderState*>(userdata);
    std::string line(buffer, size * count);
    std::string lower = line;
    for (char& c : lower)
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    const std::string prefix = "grpc-status:";
    if (lower.rfind(prefix, 0) == 0) {
        const char* value = line.c_str() + prefix.size();
        while (*value == ' ' || *value == '\t')
            ++value;
        char* end = nullptr;
        const long parsed = strtol(value, &end, 10);
        if (end != value) {
            state->saw_status = true;
            state->status = parsed;
        }
    }
    return size * count;
}
#endif

}  // namespace

bool otlp_http_available()
{
#ifdef CALLGRAPH_HAVE_CURL
    return true;
#else
    return false;
#endif
}

struct OtelExporter::HttpWorker {
    explicit HttpWorker(const OtelConfig& config) : config_(config)
    {
        thread_ = std::thread(&HttpWorker::run, this);
    }

    ~HttpWorker()
    {
        finish();
    }

    void enqueue(SpanRecord&& span)
    {
        const size_t cost = span_cost(span);
        {
            std::lock_guard<std::mutex> lock(mu_);
            if (queue_.size() >= config_.queue_spans ||
                queued_bytes_ + cost > config_.batch_bytes * 8) {
                dropped_.fetch_add(1, std::memory_order_relaxed);
                return;
            }
            queued_bytes_ += cost;
            queue_.push_back(std::move(span));
        }
        cv_.notify_one();
    }

    void finish()
    {
        {
            std::lock_guard<std::mutex> lock(mu_);
            if (finished_)
                return;
            finished_ = true;
            stop_ = true;
        }
        cv_.notify_all();
        if (thread_.joinable())
            thread_.join();
    }

    uint64_t exported() const
    {
        return exported_.load(std::memory_order_relaxed);
    }

    uint64_t dropped() const
    {
        return dropped_.load(std::memory_order_relaxed);
    }

    uint64_t failed() const
    {
        return failed_.load(std::memory_order_relaxed);
    }

private:
    void run();
    bool send(const std::vector<SpanRecord>& batch);
    bool post(const std::string& body, const char* content_type, bool grpc);

    OtelConfig config_;
    std::mutex mu_;
    std::condition_variable cv_;
    std::deque<SpanRecord> queue_;
    size_t queued_bytes_ = 0;
    bool stop_ = false;
    bool finished_ = false;
    std::thread thread_;

    std::atomic<uint64_t> exported_{0};
    std::atomic<uint64_t> dropped_{0};
    std::atomic<uint64_t> failed_{0};
    bool warned_ = false;
};

void OtelExporter::HttpWorker::run()
{
    while (true) {
        std::vector<SpanRecord> batch;
        {
            std::unique_lock<std::mutex> lock(mu_);
            if (queue_.empty()) {
                if (stop_)
                    break;
                cv_.wait_for(lock, std::chrono::milliseconds(config_.flush_ms));
            }

            size_t batch_bytes = 0;
            while (!queue_.empty() &&
                   batch.size() < config_.batch_spans) {
                const size_t cost = span_cost(queue_.front());
                if (!batch.empty() &&
                    batch_bytes + cost > config_.batch_bytes)
                    break;
                batch_bytes += cost;
                batch.push_back(std::move(queue_.front()));
                queue_.pop_front();
                queued_bytes_ = queued_bytes_ > cost ? queued_bytes_ - cost : 0;
            }

            if (batch.empty() && stop_ && queue_.empty())
                break;
        }

        if (batch.empty())
            continue;

        if (send(batch)) {
            exported_.fetch_add(batch.size(), std::memory_order_relaxed);
        } else {
            failed_.fetch_add(batch.size(), std::memory_order_relaxed);
        }
    }
}

bool OtelExporter::HttpWorker::send(const std::vector<SpanRecord>& batch)
{
    std::string body;
    const char* content_type = "application/json";
    bool grpc = false;

    switch (config_.protocol) {
    case OtlpProtocol::JsonHttp:
        body = encode_otlp_request(batch, config_);
        break;
    case OtlpProtocol::ProtobufHttp:
        body = encode_otlp_protobuf(batch, config_);
        content_type = "application/x-protobuf";
        break;
    case OtlpProtocol::Grpc:
        body = grpc_body(encode_otlp_protobuf(batch, config_));
        content_type = "application/grpc";
        grpc = true;
        break;
    }

    if (body.empty() && !batch.empty())
        return false;

    for (int attempt = 0; attempt < 3; ++attempt) {
        if (post(body, content_type, grpc))
            return true;

        if (attempt == 0) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        } else {
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
        }
    }

    if (!warned_) {
        warned_ = true;
        log_warn("OTLP export failed for %zu span(s); retries exhausted",
                 batch.size());
    }
    return false;
}

bool OtelExporter::HttpWorker::post(const std::string& body,
                                    const char* content_type, bool grpc)
{
#ifdef CALLGRAPH_HAVE_CURL
    CURL* curl = curl_easy_init();
    if (!curl)
        return false;

    std::string payload = body;
    std::string content_encoding;
    if (config_.gzip && !grpc) {
        z_stream stream = {};
        if (deflateInit2(&stream, Z_DEFAULT_COMPRESSION, Z_DEFLATED,
                         15 + 16, 8, Z_DEFAULT_STRATEGY) != Z_OK) {
            curl_easy_cleanup(curl);
            return false;
        }
        std::string compressed;
        compressed.resize(deflateBound(&stream, static_cast<uLong>(body.size())));
        stream.next_in = reinterpret_cast<Bytef*>(
            const_cast<char*>(body.data()));
        stream.avail_in = static_cast<uInt>(body.size());
        stream.next_out = reinterpret_cast<Bytef*>(compressed.data());
        stream.avail_out = static_cast<uInt>(compressed.size());
        const int result = deflate(&stream, Z_FINISH);
        if (result != Z_STREAM_END) {
            deflateEnd(&stream);
            curl_easy_cleanup(curl);
            return false;
        }
        compressed.resize(stream.total_out);
        deflateEnd(&stream);
        payload = std::move(compressed);
        content_encoding = "Content-Encoding: gzip";
    }

    const std::string url = grpc ? grpc_endpoint(config_.endpoint)
                                 : config_.endpoint;
    const std::string content_header =
        std::string("Content-Type: ") + content_type;
    struct curl_slist* headers = nullptr;
    headers = curl_slist_append(headers, content_header.c_str());
    if (!content_encoding.empty())
        headers = curl_slist_append(headers, content_encoding.c_str());
    if (grpc) {
        headers = curl_slist_append(headers, "TE: trailers");
        headers = curl_slist_append(headers, "grpc-accept-encoding: identity");
    }
    for (const auto& header : config_.headers) {
        std::string line = header;
        const size_t equals = line.find('=');
        if (equals != std::string::npos &&
            line.find(':') == std::string::npos) {
            line.replace(equals, 1, ": ");
        }
        headers = curl_slist_append(headers, line.c_str());
    }

    char error_buffer[CURL_ERROR_SIZE] = {};
    GrpcHeaderState grpc_state;
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, payload.data());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE_LARGE,
                     static_cast<curl_off_t>(payload.size()));
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS,
                     static_cast<long>(config_.timeout_ms));
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "callgraph-otlp/1");
    curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, error_buffer);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION,
                     +[](char*, size_t size, size_t count, void*) -> size_t {
                         return size * count;
                     });
    if (grpc) {
        curl_easy_setopt(curl, CURLOPT_HTTP_VERSION,
                         url.rfind("https://", 0) == 0
                             ? CURL_HTTP_VERSION_2TLS
                             : CURL_HTTP_VERSION_2_PRIOR_KNOWLEDGE);
        curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, grpc_header_callback);
        curl_easy_setopt(curl, CURLOPT_HEADERDATA, &grpc_state);
    }

    const CURLcode code = curl_easy_perform(curl);
    long response = 0;
    if (code == CURLE_OK)
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response);

    const bool grpc_ok = !grpc_state.saw_status || grpc_state.status == 0;
    const bool ok = code == CURLE_OK && response >= 200 && response < 300 &&
                    grpc_ok;
    if (!ok) {
        log_verbose("OTLP POST to %s failed: %s (HTTP %ld, gRPC %ld)",
                    url.c_str(),
                    code == CURLE_OK ? "non-2xx response" : error_buffer,
                    response, grpc_state.status);
    }

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    return ok;
#else
    (void)body;
    (void)content_type;
    (void)grpc;
    return false;
#endif
}

OtelExporter::OtelExporter(OtelConfig config) : config_(std::move(config))
{
    if (!config_.endpoint.empty()) {
        if (!otlp_http_available())
            fail("OTLP export requested but this build has no libcurl");
        if (config_.protocol != OtlpProtocol::JsonHttp &&
            !otlp_protobuf_available()) {
            fail("OTLP gRPC/protobuf export requested but this build has no "
                 "protobuf support");
        }
#ifdef CALLGRAPH_HAVE_CURL
        static std::once_flag curl_once;
        std::call_once(curl_once,
                       [] { curl_global_init(CURL_GLOBAL_DEFAULT); });
        if (config_.protocol == OtlpProtocol::Grpc) {
            const curl_version_info_data* version = curl_version_info(
                CURLVERSION_NOW);
            if (!version || !(version->features & CURL_VERSION_HTTP2))
                fail("OTLP/gRPC requires libcurl with HTTP/2 support");
        }
#endif
        http_ = std::make_unique<HttpWorker>(config_);
    }
}

OtelExporter::~OtelExporter()
{
    finish();
}

void OtelExporter::export_span(SpanRecord&& span)
{
    if (has_output()) {
        file_spans_.push_back(span);
    }
    if (http_) {
        http_->enqueue(std::move(span));
    } else if (!has_output()) {
        dropped_.fetch_add(1, std::memory_order_relaxed);
    }
}

void OtelExporter::write_file()
{
    if (config_.output_path.empty())
        return;

    const std::string body = encode_otlp_request(file_spans_, config_);
    FILE* file = fopen(config_.output_path.c_str(), "w");
    if (!file) {
        log_warn("cannot open OTLP output %s: %s", config_.output_path.c_str(),
                 errno_string(errno).c_str());
        failed_.fetch_add(file_spans_.size(), std::memory_order_relaxed);
        return;
    }
    const size_t written = fwrite(body.data(), 1, body.size(), file);
    if (written != body.size()) {
        log_warn("OTLP output write failed for %s: %s",
                 config_.output_path.c_str(), errno_string(errno).c_str());
        failed_.fetch_add(file_spans_.size(), std::memory_order_relaxed);
    } else {
        exported_.fetch_add(file_spans_.size(), std::memory_order_relaxed);
    }
    fclose(file);
}

void OtelExporter::finish()
{
    if (finished_)
        return;
    finished_ = true;

    if (http_) {
        http_->finish();
        exported_.fetch_add(http_->exported(), std::memory_order_relaxed);
        dropped_.fetch_add(http_->dropped(), std::memory_order_relaxed);
        failed_.fetch_add(http_->failed(), std::memory_order_relaxed);
        http_.reset();
    }
    write_file();
    file_spans_.clear();
}

}  // namespace callgraph
