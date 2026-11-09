#include "callgraph/probe_manager.h"

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <cerrno>
#include <cstring>
#include <algorithm>
#include <unordered_set>
#include <vector>

#include "callgraph/common.h"
#include "trace.h"
#include "trace_bpf_blob.h"

namespace callgraph {
namespace {

bool g_libbpf_verbose = false;

int libbpf_print_cb(enum libbpf_print_level level, const char* format, va_list args)
{
    if (level == LIBBPF_DEBUG && !g_libbpf_verbose)
        return 0;
    if (level == LIBBPF_INFO && !g_libbpf_verbose)
        return 0;
    return vfprintf(stderr, format, args);
}

}  // namespace

ProbeManager::ProbeManager(pid_t target, size_t ringbuf_size, size_t batch_size,
                           bool verbose)
    : target_(target), ringbuf_size_(ringbuf_size), batch_size_(batch_size),
      verbose_(verbose)
{
    g_libbpf_verbose = verbose;
    libbpf_set_print(libbpf_print_cb);
}

ProbeManager::~ProbeManager()
{
    for (bpf_link* link : links_)
        bpf_link__destroy(link);
    if (obj_)
        bpf_object__close(obj_);
}

void ProbeManager::load()
{
    obj_ = bpf_object__open_mem(bpf_trace_bpf_o, bpf_trace_bpf_o_len, nullptr);
    if (!obj_)
        fail("failed to open embedded BPF object: %s",
             errno_string(errno).c_str());

    events_map_ = bpf_object__find_map_by_name(obj_, "events");
    lost_map_ = bpf_object__find_map_by_name(obj_, "lost");
    if (!events_map_ || !lost_map_)
        fail("embedded BPF object is missing required maps");

    if (bpf_map__set_max_entries(events_map_, ringbuf_size_) != 0)
        fail("cannot set ring buffer size to %zu bytes", ringbuf_size_);

    const int err = bpf_object__load(obj_);
    if (err != 0)
        fail("failed to load BPF object: %s", errno_string(-err).c_str());

    entry_prog_ = bpf_object__find_program_by_name(obj_, "on_entry");
    exit_prog_ = bpf_object__find_program_by_name(obj_, "on_exit");
    if (!entry_prog_ || !exit_prog_)
        fail("embedded BPF object is missing required programs");
}

void ProbeManager::attach(const std::string& module_path,
                          const std::vector<FunctionInfo>& functions,
                          bool ret_mode)
{
    std::vector<uint64_t> entry_offsets;
    std::vector<uint64_t> entry_cookies;
    entry_offsets.reserve(functions.size());
    entry_cookies.reserve(functions.size());

    for (const auto& fn : functions) {
        entry_offsets.push_back(fn.file_offset);
        entry_cookies.push_back(fn.function_id);
    }

    attach_side(entry_prog_, module_path, entry_offsets, entry_cookies, false);

    if (ret_mode) {
        // Return probes are ordinary uprobes placed on `ret` instructions.
        // They do not replace the return address, so C++ unwinding keeps
        // working; frames unwound by an exception simply produce no event.
        std::vector<uint64_t> ret_offsets;
        std::vector<uint64_t> ret_cookies;
        std::unordered_set<uint64_t> seen;

        for (const auto& fn : functions) {
            for (uint64_t offset : fn.return_offsets) {
                if (!seen.insert(offset).second)
                    continue;
                ret_offsets.push_back(offset);
                ret_cookies.push_back(fn.function_id);
            }
        }

        if (ret_offsets.empty())
            log_warn("no return instructions were found; no return events will "
                     "be produced in ret mode");

        attach_side(exit_prog_, module_path, ret_offsets, ret_cookies, false);
        log_verbose("attached %zu return-instruction probe(s)", ret_offsets.size());
    } else {
        attach_side(exit_prog_, module_path, entry_offsets, entry_cookies, true);
    }

    log_verbose("attached %zu function(s) in %s (%s)", functions.size(),
                module_path.c_str(), used_multi_ ? "uprobe_multi" : "uprobe");
}

void ProbeManager::attach_side(bpf_program* prog, const std::string& path,
                               const std::vector<uint64_t>& offsets,
                               const std::vector<uint64_t>& cookies, bool retprobe)
{
    const size_t batch = batch_size_ == 0 ? 1 : batch_size_;
    for (size_t begin = 0; begin < offsets.size(); begin += batch) {
        const size_t end = std::min(begin + batch, offsets.size());
        attach_range(prog, path, offsets, cookies, begin, end, retprobe);
    }
}

void ProbeManager::attach_range(bpf_program* prog, const std::string& path,
                                const std::vector<uint64_t>& offsets,
                                const std::vector<uint64_t>& cookies,
                                size_t begin, size_t end, bool retprobe)
{
    static_assert(sizeof(unsigned long) == sizeof(uint64_t),
                  "uprobe_multi offsets are unsigned long");

    LIBBPF_OPTS(bpf_uprobe_multi_opts, opts);
    opts.offsets = reinterpret_cast<const unsigned long*>(offsets.data() + begin);
    // __u64 is unsigned long long on x86-64 while uint64_t is unsigned long.
    const std::vector<__u64> cookie_values(cookies.begin() + begin,
                                           cookies.begin() + end);
    opts.cookies = cookie_values.data();
    opts.cnt = end - begin;
    opts.retprobe = retprobe;

    bpf_link* link = bpf_program__attach_uprobe_multi(
        prog, target_, path.c_str(), nullptr, &opts);
    const long err = libbpf_get_error(link);
    if (err == 0) {
        links_.push_back(link);
        used_multi_ = true;
        return;
    }

    if (err == -EOPNOTSUPP || err == -ENOTSUP) {
        log_verbose("uprobe_multi is unavailable (%s); using individual uprobes",
                    errno_string(static_cast<int>(-err)).c_str());
        attach_single(prog, path, offsets, cookies, begin, end, retprobe);
        return;
    }

    if (end - begin > 1) {
        const size_t mid = begin + (end - begin) / 2;
        attach_range(prog, path, offsets, cookies, begin, mid, retprobe);
        attach_range(prog, path, offsets, cookies, mid, end, retprobe);
        return;
    }

    attach_single(prog, path, offsets, cookies, begin, end, retprobe);
}

void ProbeManager::attach_single(bpf_program* prog, const std::string& path,
                                 const std::vector<uint64_t>& offsets,
                                 const std::vector<uint64_t>& cookies,
                                 size_t begin, size_t end, bool retprobe)
{
    for (size_t i = begin; i < end; ++i) {
        LIBBPF_OPTS(bpf_uprobe_opts, opts);
        opts.retprobe = retprobe;
        opts.bpf_cookie = cookies[i];

        bpf_link* link = bpf_program__attach_uprobe_opts(
            prog, target_, path.c_str(), offsets[i], &opts);
        const long err = libbpf_get_error(link);
        if (err != 0) {
            ++attach_failures_;
            log_warn("cannot attach probe at %s+0x%llx: %s", path.c_str(),
                     static_cast<unsigned long long>(offsets[i]),
                     errno_string(static_cast<int>(-err)).c_str());
            continue;
        }
        links_.push_back(link);
    }
}

int ProbeManager::events_fd() const
{
    return events_map_ ? bpf_map__fd(events_map_) : -1;
}

uint64_t ProbeManager::lost_events() const
{
    if (!lost_map_)
        return 0;

    const int ncpus = libbpf_num_possible_cpus();
    if (ncpus <= 0)
        return 0;

    std::vector<uint64_t> values(static_cast<size_t>(ncpus), 0);
    uint32_t key = 0;
    if (bpf_map_lookup_elem(bpf_map__fd(lost_map_), &key, values.data()) != 0)
        return 0;

    uint64_t total = 0;
    for (uint64_t value : values)
        total += value;
    return total;
}

}  // namespace callgraph
