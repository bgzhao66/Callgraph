#ifndef CALLGRAPH_KERNEL_MM_BPF_H
#define CALLGRAPH_KERNEL_MM_BPF_H

#include "kernel/common.bpf.h"

#define CG_DEFINE_PAGE_FAULT(name, kind)                                       \
    SEC("tp/exceptions/" #name)                                                \
    int cg_##name(void *ctx)                                                   \
    {                                                                          \
        struct cg_tp_config *cfg = tp_config_for(kind);                        \
        __u64 address = 0, ip = 0, error_code = 0;                             \
        if (tp_read(ctx, cfg, 0, &address) != 0 ||                             \
            tp_read(ctx, cfg, 1, &ip) != 0 ||                                  \
            tp_read(ctx, cfg, 2, &error_code) != 0)                            \
            return 0;                                                          \
        const __u64 current = bpf_get_current_pid_tgid();                       \
        const __u32 tid = (__u32)current;                                       \
        if (!is_target_tid(tid))                                                \
            return 0;                                                          \
        emit_kernel(kind, CG_KCAT_MM, CG_KF_DIRECT, tid,                       \
                    (__u32)(current >> 32), 0, 0, address, ip, error_code,     \
                    0, 0, 0, 0, 0);                                            \
        return 0;                                                              \
    }

CG_DEFINE_PAGE_FAULT(page_fault_user, CG_KEV_PAGE_FAULT_USER)
CG_DEFINE_PAGE_FAULT(page_fault_kernel, CG_KEV_PAGE_FAULT_KERNEL)

SEC("tp/vmscan/mm_vmscan_direct_reclaim_begin")
int cg_direct_reclaim_begin(void *ctx)
{
    struct cg_tp_config *cfg = tp_config_for(CG_KEV_DIRECT_RECLAIM_BEGIN);
    __u64 order = 0, gfp_flags = 0;
    if (tp_read(ctx, cfg, 0, &order) != 0 ||
        tp_read_opt(ctx, cfg, 1, &gfp_flags) != 0)
        return 0;

    const __u64 current = bpf_get_current_pid_tgid();
    const __u32 tid = (__u32)current;
    if (!is_target_tid(tid))
        return 0;

    emit_kernel(CG_KEV_DIRECT_RECLAIM_BEGIN, CG_KCAT_MM,
                CG_KF_DIRECT | CG_KF_BEGIN, tid, (__u32)(current >> 32), 0, 0,
                order, gfp_flags, 0, 0, 0, 0, 0, 0);
    return 0;
}

SEC("tp/vmscan/mm_vmscan_direct_reclaim_end")
int cg_direct_reclaim_end(void *ctx)
{
    struct cg_tp_config *cfg = tp_config_for(CG_KEV_DIRECT_RECLAIM_END);
    __u64 nr_reclaimed = 0;
    if (tp_read_opt(ctx, cfg, 0, &nr_reclaimed) != 0)
        return 0;

    const __u64 current = bpf_get_current_pid_tgid();
    const __u32 tid = (__u32)current;
    if (!is_target_tid(tid))
        return 0;

    emit_kernel(CG_KEV_DIRECT_RECLAIM_END, CG_KCAT_MM,
                CG_KF_DIRECT | CG_KF_END, tid, (__u32)(current >> 32), 0, 0,
                nr_reclaimed, 0, 0, 0, 0, 0, 0, 0);
    return 0;
}

#endif /* CALLGRAPH_KERNEL_MM_BPF_H */
