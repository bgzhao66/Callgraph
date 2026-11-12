#include "callgraph/trace_metadata.h"

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <sstream>

#include "callgraph/common.h"

namespace callgraph {
namespace {

std::string escape_field(const std::string& value)
{
    std::string out;
    out.reserve(value.size());
    for (char c : value) {
        switch (c) {
        case '\\':
            out += "\\\\";
            break;
        case '\t':
            out += "\\t";
            break;
        case '\n':
            out += "\\n";
            break;
        case '\r':
            out += "\\r";
            break;
        default:
            out.push_back(c);
            break;
        }
    }
    return out;
}

std::string unescape_field(const std::string& value)
{
    std::string out;
    out.reserve(value.size());
    for (size_t i = 0; i < value.size(); ++i) {
        if (value[i] != '\\' || i + 1 >= value.size()) {
            out.push_back(value[i]);
            continue;
        }
        switch (value[++i]) {
        case 't':
            out.push_back('\t');
            break;
        case 'n':
            out.push_back('\n');
            break;
        case 'r':
            out.push_back('\r');
            break;
        case '\\':
            out.push_back('\\');
            break;
        default:
            out.push_back('\\');
            out.push_back(value[i]);
            break;
        }
    }
    return out;
}

std::vector<std::string> split_tabs(const std::string& line)
{
    std::vector<std::string> fields;
    size_t start = 0;
    while (start <= line.size()) {
        const size_t end = line.find('\t', start);
        if (end == std::string::npos) {
            fields.push_back(line.substr(start));
            break;
        }
        fields.push_back(line.substr(start, end - start));
        start = end + 1;
    }
    return fields;
}

uint64_t parse_u64(const std::string& text)
{
    char* end = nullptr;
    errno = 0;
    const unsigned long long value = strtoull(text.c_str(), &end, 0);
    if (errno != 0 || end == text.c_str())
        return 0;
    return static_cast<uint64_t>(value);
}

}  // namespace

bool write_trace_metadata(const std::string& path,
                          const TraceMetadata& metadata)
{
    if (path.empty())
        return true;

    FILE* file = fopen(path.c_str(), "w");
    if (!file) {
        log_warn("cannot open metadata file %s: %s", path.c_str(),
                 errno_string(errno).c_str());
        return false;
    }

    fprintf(file, "callgraph-trace-metadata\t2\n");
    fprintf(file, "service.name\t%s\n",
            escape_field(metadata.service_name).c_str());
    fprintf(file, "service.namespace\t%s\n",
            escape_field(metadata.service_namespace).c_str());
    fprintf(file, "service.instance.id\t%s\n",
            escape_field(metadata.service_instance_id).c_str());
    fprintf(file, "pid\t%ld\n", static_cast<long>(metadata.pid));
    fprintf(file, "monotonic_offset_ns\t%llu\n",
            static_cast<unsigned long long>(metadata.monotonic_offset_ns));
    fprintf(file, "seed_hi\t%llu\n",
            static_cast<unsigned long long>(metadata.seed_hi));
    fprintf(file, "seed_lo\t%llu\n",
            static_cast<unsigned long long>(metadata.seed_lo));
    fprintf(file, "return_mode\t%s\n",
            escape_field(metadata.return_mode).c_str());
    fprintf(file, "trace_scope\t%s\n",
            escape_field(metadata.trace_scope).c_str());
    fprintf(file, "attach_mode\t%d\n", metadata.attach_mode ? 1 : 0);

    for (size_t i = 0; i < metadata.functions.size(); ++i) {
        const FunctionMetadata& function = metadata.functions[i];
        fprintf(file, "function\t%zu\t%s\t%s\t%s\t0x%llx\t%s\t%u\t%s\n", i,
                escape_field(function.name).c_str(),
                escape_field(function.module_path).c_str(),
                escape_field(function.module_build_id).c_str(),
                static_cast<unsigned long long>(function.file_offset),
                escape_field(function.source_file).c_str(),
                function.source_line,
                escape_field(function.linkage_name).c_str());
    }

    if (fclose(file) != 0) {
        log_warn("cannot finish metadata file %s: %s", path.c_str(),
                 errno_string(errno).c_str());
        return false;
    }
    return true;
}

bool read_trace_metadata(const std::string& path, TraceMetadata* metadata)
{
    *metadata = TraceMetadata{};
    if (path.empty())
        return false;

    std::ifstream input(path);
    if (!input)
        return false;

    std::string line;
    bool header = false;
    while (std::getline(input, line)) {
        const auto fields = split_tabs(line);
        if (fields.empty())
            continue;
        if (fields[0] == "callgraph-trace-metadata") {
            header = true;
            continue;
        }
        if (fields[0] == "service.name" && fields.size() >= 2)
            metadata->service_name = unescape_field(fields[1]);
        else if (fields[0] == "service.namespace" && fields.size() >= 2)
            metadata->service_namespace = unescape_field(fields[1]);
        else if (fields[0] == "service.instance.id" && fields.size() >= 2)
            metadata->service_instance_id = unescape_field(fields[1]);
        else if (fields[0] == "pid" && fields.size() >= 2)
            metadata->pid = static_cast<pid_t>(parse_u64(fields[1]));
        else if (fields[0] == "monotonic_offset_ns" && fields.size() >= 2)
            metadata->monotonic_offset_ns = parse_u64(fields[1]);
        else if (fields[0] == "seed_hi" && fields.size() >= 2)
            metadata->seed_hi = parse_u64(fields[1]);
        else if (fields[0] == "seed_lo" && fields.size() >= 2)
            metadata->seed_lo = parse_u64(fields[1]);
        else if (fields[0] == "return_mode" && fields.size() >= 2)
            metadata->return_mode = unescape_field(fields[1]);
        else if (fields[0] == "trace_scope" && fields.size() >= 2)
            metadata->trace_scope = unescape_field(fields[1]);
        else if (fields[0] == "attach_mode" && fields.size() >= 2)
            metadata->attach_mode = parse_u64(fields[1]) != 0;
        else if (fields[0] == "function" && fields.size() >= 9) {
            FunctionMetadata function;
            function.name = unescape_field(fields[2]);
            function.module_path = unescape_field(fields[3]);
            function.module_build_id = unescape_field(fields[4]);
            function.file_offset = parse_u64(fields[5]);
            function.source_file = unescape_field(fields[6]);
            function.source_line = static_cast<uint32_t>(parse_u64(fields[7]));
            function.linkage_name = unescape_field(fields[8]);
            metadata->functions.push_back(std::move(function));
        } else if (fields[0] == "function" && fields.size() >= 7) {
            FunctionMetadata function;
            function.name = unescape_field(fields[2]);
            function.module_path = unescape_field(fields[3]);
            function.module_build_id = unescape_field(fields[4]);
            function.file_offset = parse_u64(fields[5]);
            function.linkage_name = unescape_field(fields[6]);
            metadata->functions.push_back(std::move(function));
        }
    }

    metadata->present = header;
    return header;
}

std::unordered_map<std::string, FunctionMetadata>
metadata_by_name(const TraceMetadata& metadata)
{
    std::unordered_map<std::string, FunctionMetadata> result;
    for (const auto& function : metadata.functions)
        result.emplace(function.name, function);
    return result;
}

}  // namespace callgraph
