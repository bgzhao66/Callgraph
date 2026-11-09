#pragma once

#include <sys/types.h>

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "callgraph/function_info.h"

struct bpf_object;
struct bpf_program;
struct bpf_map;
struct bpf_link;

namespace callgraph {

// Owns the BPF object and the uprobe/uretprobe links.
class ProbeManager {
public:
    ProbeManager(pid_t target, size_t ringbuf_size, size_t batch_size, bool verbose);
    ~ProbeManager();

    ProbeManager(const ProbeManager&) = delete;
    ProbeManager& operator=(const ProbeManager&) = delete;

    void load();
    void attach(const std::string& module_path,
                const std::vector<FunctionInfo>& functions, bool ret_mode);

    int events_fd() const;
    uint64_t lost_events() const;
    bool used_multi_attach() const { return used_multi_; }
    uint64_t attach_failures() const { return attach_failures_; }

private:
    void attach_side(bpf_program* prog, const std::string& path,
                     const std::vector<uint64_t>& offsets,
                     const std::vector<uint64_t>& cookies, bool retprobe);
    void attach_range(bpf_program* prog, const std::string& path,
                      const std::vector<uint64_t>& offsets,
                      const std::vector<uint64_t>& cookies,
                      size_t begin, size_t end, bool retprobe);
    void attach_single(bpf_program* prog, const std::string& path,
                       const std::vector<uint64_t>& offsets,
                       const std::vector<uint64_t>& cookies,
                       size_t begin, size_t end, bool retprobe);

    pid_t target_;
    size_t ringbuf_size_;
    size_t batch_size_;
    bool verbose_;

    bpf_object* obj_ = nullptr;
    bpf_program* entry_prog_ = nullptr;
    bpf_program* exit_prog_ = nullptr;
    bpf_map* events_map_ = nullptr;
    bpf_map* lost_map_ = nullptr;

    std::vector<bpf_link*> links_;
    bool used_multi_ = false;
    uint64_t attach_failures_ = 0;
};

}  // namespace callgraph
