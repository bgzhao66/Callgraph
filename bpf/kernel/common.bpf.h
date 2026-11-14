#ifndef CALLGRAPH_KERNEL_COMMON_BPF_H
#define CALLGRAPH_KERNEL_COMMON_BPF_H

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#include "kernel_event.h"

static __always_inline struct cg_kernel_config *kernel_config_value(void)
{
    __u32 key = 0;
    return bpf_map_lookup_elem(&kernel_config, &key);
}

static __always_inline int is_target_tid(__u32 tid)
{
    struct cg_kernel_config *config = kernel_config_value();
    if (!config)
        return 0;
    if (config->system_wide)
        return 1;

    __u8 *value = bpf_map_lookup_elem(&target_tids, &tid);
    return value != 0;
}

static __always_inline struct cg_tp_config *tp_config_for(__u16 kind)
{
    __u32 key = kind;
    return bpf_map_lookup_elem(&tp_config, &key);
}

static __always_inline int tp_read_size(void *ctx, struct cg_tp_config *cfg,
                                        __u32 index, __u64 *out, int optional)
{
    if (!cfg)
        return -1;
    const __u16 offset = cfg->field[index].offset;
    const __u8 size = cfg->field[index].size;
    if (size == 0) {
        if (optional) {
            *out = 0;
            return 0;
        }
        return -1;
    }
    if (size == 1) {
        __u8 value = 0;
        if (bpf_probe_read_kernel(&value, sizeof(value),
                                  (char *)ctx + offset) != 0)
            return -1;
        *out = value;
        return 0;
    }
    if (size == 2) {
        __u16 value = 0;
        if (bpf_probe_read_kernel(&value, sizeof(value),
                                  (char *)ctx + offset) != 0)
            return -1;
        *out = value;
        return 0;
    }
    if (size == 4) {
        __u32 value = 0;
        if (bpf_probe_read_kernel(&value, sizeof(value),
                                  (char *)ctx + offset) != 0)
            return -1;
        *out = value;
        return 0;
    }
    if (size == 8) {
        __u64 value = 0;
        if (bpf_probe_read_kernel(&value, sizeof(value),
                                  (char *)ctx + offset) != 0)
            return -1;
        *out = value;
        return 0;
    }
    return -1;
}

static __always_inline int tp_read(void *ctx, struct cg_tp_config *cfg,
                                   __u32 index, __u64 *out)
{
    return tp_read_size(ctx, cfg, index, out, 0);
}

static __always_inline int tp_read_opt(void *ctx, struct cg_tp_config *cfg,
                                       __u32 index, __u64 *out)
{
    return tp_read_size(ctx, cfg, index, out, 1);
}

static __always_inline void count_lost(__u8 category)
{
    __u32 key = category;
    __u64 *lost = bpf_map_lookup_elem(&kernel_lost, &key);
    if (lost)
        __sync_fetch_and_add(lost, 1);
}

static __always_inline void emit_kernel(__u16 kind, __u8 category, __u8 flags,
                                        __u32 tid, __u32 tgid, __u32 peer_tid,
                                        __u32 peer_tgid, __u64 a, __u64 b,
                                        __u64 c, __u64 d, __u64 e, __u64 f,
                                        __u64 g, __u64 h)
{
    struct cg_kernel_event *event =
        bpf_ringbuf_reserve(&kernel_events, sizeof(*event), 0);
    if (!event) {
        count_lost(category);
        return;
    }

    event->ts = bpf_ktime_get_ns();
    event->tid = tid;
    event->tgid = tgid;
    event->peer_tid = peer_tid;
    event->peer_tgid = peer_tgid;
    event->cpu = bpf_get_smp_processor_id();
    event->kind = kind;
    event->category = category;
    event->flags = flags;
    event->a = a;
    event->b = b;
    event->c = c;
    event->d = d;
    event->e = e;
    event->f = f;
    event->g = g;
    event->h = h;

    bpf_ringbuf_submit(event, 0);
}

#endif /* CALLGRAPH_KERNEL_COMMON_BPF_H */
