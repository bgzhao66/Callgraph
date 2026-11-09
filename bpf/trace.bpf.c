#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#include "trace.h"

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} lost SEC(".maps");

static __always_inline int emit_event(void *ctx, __u8 type)
{
    __u64 id = bpf_get_current_pid_tgid();
    __u32 key = 0;
    __u64 *lost_count;
    struct cg_event *e;

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        lost_count = bpf_map_lookup_elem(&lost, &key);
        if (lost_count)
            __sync_fetch_and_add(lost_count, 1);
        return 0;
    }

    e->ts = bpf_ktime_get_ns();
    e->func_id = bpf_get_attach_cookie(ctx);
    e->tgid = (__u32)(id >> 32);
    e->tid = (__u32)id;
    e->type = type;
    __builtin_memset(e->pad, 0, sizeof(e->pad));

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("uprobe.multi")
int on_entry(void *ctx)
{
    return emit_event(ctx, CG_EVENT_ENTER);
}

SEC("uretprobe.multi")
int on_exit(void *ctx)
{
    return emit_event(ctx, CG_EVENT_EXIT);
}

char LICENSE[] SEC("license") = "GPL";
