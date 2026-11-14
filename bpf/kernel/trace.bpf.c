#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#include "kernel_event.h"

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} kernel_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 16);
    __type(key, __u32);
    __type(value, __u64);
} kernel_lost SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, __u32);
    __type(value, __u8);
} target_tids SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 64);
    __type(key, __u32);
    __type(value, struct cg_tp_config);
} tp_config SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct cg_kernel_config);
} kernel_config SEC(".maps");

#include "kernel/sched.bpf.h"
#include "kernel/syscall.bpf.h"
#include "kernel/block.bpf.h"
#include "kernel/mm.bpf.h"
#include "kernel/net.bpf.h"

char LICENSE[] SEC("license") = "GPL";
