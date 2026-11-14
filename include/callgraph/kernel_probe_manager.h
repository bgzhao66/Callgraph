#pragma once

#include <sys/types.h>

#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include <kernel_event.h>

struct bpf_object;
struct bpf_program;
struct bpf_map;
struct bpf_link;

namespace callgraph {

struct KernelSelection {
    bool sched = false;
    bool futex = false;
    bool io = false;
    bool block = false;
    bool memory = false;
    bool network = false;

    bool any() const
    {
        return sched || futex || io || block || memory || network;
    }
};

// Owns the kernel-event BPF object, its maps, and tracepoint links.  The
// object is loaded only when at least one kernel family is requested.
class KernelProbeManager {
public:
    KernelProbeManager(size_t ringbuf_size, bool verbose);
    ~KernelProbeManager();

    KernelProbeManager(const KernelProbeManager&) = delete;
    KernelProbeManager& operator=(const KernelProbeManager&) = delete;

    void load();
    void set_target_tids(const std::vector<uint32_t>& tids);
    void add_target_tid(uint32_t tid);
    void set_system_wide(bool enabled);
    void attach(const KernelSelection& selection, bool require);

    int events_fd() const;
    uint64_t lost_events() const;
    uint64_t attached_events() const { return attached_events_; }
    uint64_t missing_events() const { return missing_events_; }
    uint64_t attach_failures() const { return attach_failures_; }

    struct FieldInfo {
        uint16_t offset = 0;
        uint8_t size = 0;
    };

    struct EventSpec {
        const char* program;
        const char* group;
        const char* name;
        uint16_t kind;
        uint8_t category;
        uint32_t family;
        const char* fields[CG_TP_MAX_FIELDS];
    };

private:
    bool apply_tp_config(const EventSpec& spec, uint16_t kind,
                         const std::unordered_map<std::string, FieldInfo>&
                             fields);
    bool read_format(const std::string& tracefs, const EventSpec& spec,
                     std::unordered_map<std::string, FieldInfo>* fields);

    size_t ringbuf_size_;
    bool verbose_;

    bpf_object* obj_ = nullptr;
    bpf_map* events_map_ = nullptr;
    bpf_map* lost_map_ = nullptr;
    bpf_map* target_tids_map_ = nullptr;
    bpf_map* tp_config_map_ = nullptr;
    bpf_map* kernel_config_map_ = nullptr;

    std::vector<bpf_link*> links_;
    std::unordered_set<uint32_t> targets_;
    uint64_t attached_events_ = 0;
    uint64_t missing_events_ = 0;
    uint64_t attach_failures_ = 0;
};

}  // namespace callgraph
