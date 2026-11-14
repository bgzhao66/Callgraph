#include "callgraph/kernel_probe_manager.h"

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <algorithm>
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <string>
#include <unordered_map>
#include <vector>

#include "callgraph/common.h"
#include "kernel_event.h"
#include "kernel_bpf_blob.h"

namespace callgraph {
namespace {

enum FamilyBit {
    kFamilySched = 1u << 0,
    kFamilyFutex = 1u << 1,
    kFamilyIo = 1u << 2,
    kFamilyBlock = 1u << 3,
};

std::string trim(std::string text)
{
    const size_t first = text.find_first_not_of(" \t\r\n");
    if (first == std::string::npos)
        return {};
    const size_t last = text.find_last_not_of(" \t\r\n");
    return text.substr(first, last - first + 1);
}

bool selected(const KernelSelection& selection, uint32_t family)
{
    if ((family & kFamilySched) && selection.sched)
        return true;
    if ((family & kFamilyFutex) && selection.futex)
        return true;
    if ((family & kFamilyIo) && selection.io)
        return true;
    if ((family & kFamilyBlock) && selection.block)
        return true;
    return false;
}

std::string find_tracefs()
{
    for (const char* path : {"/sys/kernel/tracing", "/sys/kernel/debug/tracing"}) {
        std::error_code error;
        if (std::filesystem::exists(std::string(path) + "/events", error))
            return path;
    }
    return {};
}

}  // namespace

namespace {

const KernelProbeManager::EventSpec kEvents[] = {
    {"cg_sched_switch", "sched", "sched_switch", CG_KEV_SCHED_SWITCH,
     CG_KCAT_SCHED, kFamilySched,
     {"prev_pid", "prev_state", "prev_prio", "next_pid", "next_prio"}},
    {"cg_sched_wakeup", "sched", "sched_wakeup", CG_KEV_SCHED_WAKEUP,
     CG_KCAT_SCHED, kFamilySched, {"pid", "prio", "target_cpu"}},
    {"cg_sched_waking", "sched", "sched_waking", CG_KEV_SCHED_WAKING,
     CG_KCAT_SCHED, kFamilySched, {"pid", "prio", "target_cpu"}},
    {"cg_sched_wakeup_new", "sched", "sched_wakeup_new",
     CG_KEV_SCHED_WAKEUP_NEW, CG_KCAT_SCHED, kFamilySched,
     {"pid", "prio", "target_cpu"}},
    {"cg_sched_migrate", "sched", "sched_migrate_task",
     CG_KEV_SCHED_MIGRATE, CG_KCAT_SCHED, kFamilySched,
     {"pid", "prio", "orig_cpu", "dest_cpu"}},
    {"cg_proc_fork", "sched", "sched_process_fork", CG_KEV_PROC_FORK,
     CG_KCAT_SCHED, kFamilySched, {"parent_pid", "child_pid"}},
    {"cg_proc_exit", "sched", "sched_process_exit", CG_KEV_PROC_EXIT,
     CG_KCAT_SCHED, kFamilySched, {"pid", "prio"}},

    {"cg_sys_enter_futex", "syscalls", "sys_enter_futex",
     CG_KEV_FUTEX_ENTER, CG_KCAT_FUTEX, kFamilyFutex,
     {"__syscall_nr", "uaddr", "op", "val", "utime", "uaddr2", "val3"}},
    {"cg_sys_exit_futex", "syscalls", "sys_exit_futex", CG_KEV_FUTEX_EXIT,
     CG_KCAT_FUTEX, kFamilyFutex, {"__syscall_nr", "ret"}},

    {"cg_sys_enter_read", "syscalls", "sys_enter_read", CG_KEV_READ_ENTER,
     CG_KCAT_IO, kFamilyIo, {"__syscall_nr", "fd", "buf", "count"}},
    {"cg_sys_exit_read", "syscalls", "sys_exit_read", CG_KEV_READ_EXIT,
     CG_KCAT_IO, kFamilyIo, {"__syscall_nr", "ret"}},
    {"cg_sys_enter_write", "syscalls", "sys_enter_write", CG_KEV_WRITE_ENTER,
     CG_KCAT_IO, kFamilyIo, {"__syscall_nr", "fd", "buf", "count"}},
    {"cg_sys_exit_write", "syscalls", "sys_exit_write", CG_KEV_WRITE_EXIT,
     CG_KCAT_IO, kFamilyIo, {"__syscall_nr", "ret"}},
    {"cg_sys_enter_pread64", "syscalls", "sys_enter_pread64",
     CG_KEV_PREAD64_ENTER, CG_KCAT_IO, kFamilyIo,
     {"__syscall_nr", "fd", "buf", "count", "pos"}},
    {"cg_sys_exit_pread64", "syscalls", "sys_exit_pread64",
     CG_KEV_PREAD64_EXIT, CG_KCAT_IO, kFamilyIo, {"__syscall_nr", "ret"}},
    {"cg_sys_enter_pwrite64", "syscalls", "sys_enter_pwrite64",
     CG_KEV_PWRITE64_ENTER, CG_KCAT_IO, kFamilyIo,
     {"__syscall_nr", "fd", "buf", "count", "pos"}},
    {"cg_sys_exit_pwrite64", "syscalls", "sys_exit_pwrite64",
     CG_KEV_PWRITE64_EXIT, CG_KCAT_IO, kFamilyIo, {"__syscall_nr", "ret"}},
    {"cg_sys_enter_fsync", "syscalls", "sys_enter_fsync", CG_KEV_FSYNC_ENTER,
     CG_KCAT_IO, kFamilyIo, {"__syscall_nr", "fd"}},
    {"cg_sys_exit_fsync", "syscalls", "sys_exit_fsync", CG_KEV_FSYNC_EXIT,
     CG_KCAT_IO, kFamilyIo, {"__syscall_nr", "ret"}},
    {"cg_sys_enter_fdatasync", "syscalls", "sys_enter_fdatasync",
     CG_KEV_FDATASYNC_ENTER, CG_KCAT_IO, kFamilyIo,
     {"__syscall_nr", "fd"}},
    {"cg_sys_exit_fdatasync", "syscalls", "sys_exit_fdatasync",
     CG_KEV_FDATASYNC_EXIT, CG_KCAT_IO, kFamilyIo,
     {"__syscall_nr", "ret"}},
    {"cg_sys_enter_openat", "syscalls", "sys_enter_openat",
     CG_KEV_OPENAT_ENTER, CG_KCAT_IO, kFamilyIo,
     {"__syscall_nr", "dfd", "filename", "flags", "mode"}},
    {"cg_sys_exit_openat", "syscalls", "sys_exit_openat", CG_KEV_OPENAT_EXIT,
     CG_KCAT_IO, kFamilyIo, {"__syscall_nr", "ret"}},
    {"cg_sys_enter_close", "syscalls", "sys_enter_close", CG_KEV_CLOSE_ENTER,
     CG_KCAT_IO, kFamilyIo, {"__syscall_nr", "fd"}},
    {"cg_sys_exit_close", "syscalls", "sys_exit_close", CG_KEV_CLOSE_EXIT,
     CG_KCAT_IO, kFamilyIo, {"__syscall_nr", "ret"}},
    {"cg_sys_enter_sync_file_range", "syscalls", "sys_enter_sync_file_range",
     CG_KEV_SYNC_FILE_RANGE_ENTER, CG_KCAT_IO, kFamilyIo,
     {"__syscall_nr", "fd", "offset", "nbytes", "flags"}},
    {"cg_sys_exit_sync_file_range", "syscalls", "sys_exit_sync_file_range",
     CG_KEV_SYNC_FILE_RANGE_EXIT, CG_KCAT_IO, kFamilyIo,
     {"__syscall_nr", "ret"}},

    {"cg_block_block_rq_insert", "block", "block_rq_insert",
     CG_KEV_BLOCK_INSERT, CG_KCAT_BLOCK, kFamilyBlock,
     {"dev", "sector", "nr_sector", "bytes"}},
    {"cg_block_block_rq_issue", "block", "block_rq_issue",
     CG_KEV_BLOCK_ISSUE, CG_KCAT_BLOCK, kFamilyBlock,
     {"dev", "sector", "nr_sector", "bytes"}},
    {"cg_block_block_rq_complete", "block", "block_rq_complete",
     CG_KEV_BLOCK_COMPLETE, CG_KCAT_BLOCK, kFamilyBlock,
     {"dev", "sector", "nr_sector", "error"}},
    {"cg_block_block_rq_requeue", "block", "block_rq_requeue",
     CG_KEV_BLOCK_REQUEUE, CG_KCAT_BLOCK, kFamilyBlock,
     {"dev", "sector", "nr_sector"}},
    {"cg_block_block_rq_error", "block", "block_rq_error",
     CG_KEV_BLOCK_ERROR, CG_KCAT_BLOCK, kFamilyBlock,
     {"dev", "sector", "nr_sector", "error"}},
};

}  // namespace

KernelProbeManager::KernelProbeManager(size_t ringbuf_size, bool verbose)
    : ringbuf_size_(ringbuf_size), verbose_(verbose)
{
}

KernelProbeManager::~KernelProbeManager()
{
    for (bpf_link* link : links_)
        bpf_link__destroy(link);
    if (obj_)
        bpf_object__close(obj_);
}

void KernelProbeManager::load()
{
    obj_ = bpf_object__open_mem(bpf_kernel_bpf_o, bpf_kernel_bpf_o_len,
                                nullptr);
    if (!obj_)
        fail("failed to open embedded kernel BPF object: %s",
             errno_string(errno).c_str());

    events_map_ = bpf_object__find_map_by_name(obj_, "kernel_events");
    lost_map_ = bpf_object__find_map_by_name(obj_, "kernel_lost");
    target_tids_map_ = bpf_object__find_map_by_name(obj_, "target_tids");
    tp_config_map_ = bpf_object__find_map_by_name(obj_, "tp_config");
    kernel_config_map_ = bpf_object__find_map_by_name(obj_, "kernel_config");
    if (!events_map_ || !lost_map_ || !target_tids_map_ || !tp_config_map_ ||
        !kernel_config_map_)
        fail("embedded kernel BPF object is missing required maps");

    if (bpf_map__set_max_entries(events_map_, ringbuf_size_) != 0)
        fail("cannot set kernel ring buffer size to %zu bytes", ringbuf_size_);

    const int err = bpf_object__load(obj_);
    if (err != 0)
        fail("failed to load kernel BPF object: %s", errno_string(-err).c_str());
}

void KernelProbeManager::set_system_wide(bool enabled)
{
    if (!kernel_config_map_)
        return;
    uint32_t key = 0;
    cg_kernel_config config = {};
    config.system_wide = enabled ? 1 : 0;
    const int err = bpf_map_update_elem(bpf_map__fd(kernel_config_map_), &key,
                                        &config, BPF_ANY);
    if (err != 0)
        fail("cannot configure kernel BPF filtering: %s",
             errno_string(-err).c_str());
}

void KernelProbeManager::set_target_tids(const std::vector<uint32_t>& tids)
{
    for (uint32_t tid : tids)
        add_target_tid(tid);
}

void KernelProbeManager::add_target_tid(uint32_t tid)
{
    if (!target_tids_map_)
        return;
    if (targets_.count(tid) != 0)
        return;

    const int fd = bpf_map__fd(target_tids_map_);
    uint8_t value = 1;
    const int err = bpf_map_update_elem(fd, &tid, &value, BPF_NOEXIST);
    if (err != 0 && err != -EEXIST) {
        log_warn("cannot add target tid %u: %s", tid,
                 errno_string(-err).c_str());
        return;
    }
    targets_.insert(tid);
}

bool KernelProbeManager::read_format(
    const std::string& tracefs, const EventSpec& spec,
    std::unordered_map<std::string, FieldInfo>* fields)
{
    const std::string path = tracefs + "/events/" + spec.group + "/" +
                             spec.name + "/format";
    std::ifstream input(path);
    if (!input)
        return false;

    std::string line;
    while (std::getline(input, line)) {
        line = trim(line);
        if (line.rfind("field:", 0) != 0)
            continue;
        const size_t semi = line.find(';');
        if (semi == std::string::npos)
            continue;
        std::string declaration = trim(line.substr(6, semi - 6));
        const size_t space = declaration.find_last_of(" \t");
        std::string name = space == std::string::npos
                               ? declaration
                               : declaration.substr(space + 1);
        if (name.find('[') != std::string::npos)
            continue;

        const size_t offset_pos = line.find("offset:");
        const size_t size_pos = line.find("size:");
        if (offset_pos == std::string::npos || size_pos == std::string::npos)
            continue;
        const unsigned long offset =
            strtoul(line.c_str() + offset_pos + 7, nullptr, 10);
        const unsigned long size =
            strtoul(line.c_str() + size_pos + 5, nullptr, 10);
        if (offset > UINT16_MAX || size > UINT8_MAX)
            continue;
        (*fields)[name] = FieldInfo{static_cast<uint16_t>(offset),
                                    static_cast<uint8_t>(size)};
    }
    return !fields->empty();
}

bool KernelProbeManager::apply_tp_config(
    const EventSpec& spec, uint16_t kind,
    const std::unordered_map<std::string, FieldInfo>& fields)
{
    cg_tp_config config = {};
    for (size_t i = 0; i < CG_TP_MAX_FIELDS; ++i) {
        const char* name = spec.fields[i];
        if (!name)
            break;
        const auto it = fields.find(name);
        if (it == fields.end()) {
            log_warn("kernel tracepoint %s:%s is missing field %s", spec.group,
                     spec.name, name);
            ++missing_events_;
            return false;
        }
        if (it->second.size != 4 && it->second.size != 8) {
            log_warn("kernel tracepoint %s:%s field %s has unsupported size %u",
                     spec.group, spec.name, name, it->second.size);
            ++missing_events_;
            return false;
        }
        config.field[i].offset = it->second.offset;
        config.field[i].size = it->second.size;
    }

    uint32_t key = kind;
    const int err = bpf_map_update_elem(bpf_map__fd(tp_config_map_), &key,
                                        &config, BPF_ANY);
    if (err != 0)
        fail("cannot configure kernel tracepoint %s:%s: %s", spec.group,
             spec.name, errno_string(-err).c_str());
    if (verbose_)
        log_verbose("kernel tracepoint %s:%s configured", spec.group,
                    spec.name);
    return true;
}

void KernelProbeManager::attach(const KernelSelection& selection, bool require)
{
    if (!selection.any())
        return;

    const std::string tracefs = find_tracefs();
    if (tracefs.empty())
        fail("kernel events require tracefs; mount tracefs at "
             "/sys/kernel/tracing or /sys/kernel/debug/tracing");

    for (const EventSpec& spec : kEvents) {
        if (!selected(selection, spec.family))
            continue;

        std::unordered_map<std::string, FieldInfo> fields;
        if (!read_format(tracefs, spec, &fields)) {
            log_warn("kernel tracepoint %s:%s is not available", spec.group,
                     spec.name);
            ++missing_events_;
            continue;
        }

        if (!apply_tp_config(spec, spec.kind, fields))
            continue;

        bpf_program* program =
            bpf_object__find_program_by_name(obj_, spec.program);
        if (!program) {
            log_warn("kernel BPF program %s is missing", spec.program);
            ++missing_events_;
            continue;
        }

        bpf_link* link =
            bpf_program__attach_tracepoint(program, spec.group, spec.name);
        const long error = libbpf_get_error(link);
        if (error != 0) {
            ++attach_failures_;
            log_warn("cannot attach kernel tracepoint %s:%s: %s", spec.group,
                     spec.name, errno_string(static_cast<int>(-error)).c_str());
            continue;
        }
        links_.push_back(link);
        ++attached_events_;
    }

    if (require && (missing_events_ != 0 || attach_failures_ != 0))
        fail("--require-events: %llu unavailable and %llu failed to "
             "attach",
             static_cast<unsigned long long>(missing_events_),
             static_cast<unsigned long long>(attach_failures_));

    if (attached_events_ == 0)
        log_warn("no kernel tracepoints were attached");
}

int KernelProbeManager::events_fd() const
{
    return events_map_ ? bpf_map__fd(events_map_) : -1;
}

uint64_t KernelProbeManager::lost_events() const
{
    if (!lost_map_)
        return 0;
    const int ncpus = libbpf_num_possible_cpus();
    if (ncpus <= 0)
        return 0;

    std::vector<uint64_t> values(static_cast<size_t>(ncpus), 0);
    uint64_t total = 0;
    for (uint32_t key = 0; key < 16; ++key) {
        if (bpf_map_lookup_elem(bpf_map__fd(lost_map_), &key, values.data()) !=
            0)
            continue;
        for (uint64_t value : values)
            total += value;
    }
    return total;
}

}  // namespace callgraph
