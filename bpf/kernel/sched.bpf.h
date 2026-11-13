#ifndef CALLGRAPH_KERNEL_SCHED_BPF_H
#define CALLGRAPH_KERNEL_SCHED_BPF_H

#include "kernel/common.bpf.h"

SEC("tp/sched/sched_switch")
int cg_sched_switch(void *ctx)
{
    struct cg_tp_config *cfg = tp_config_for(CG_KEV_SCHED_SWITCH);
    __u64 prev_pid = 0, prev_state = 0, prev_prio = 0;
    __u64 next_pid = 0, next_prio = 0;
    if (tp_read(ctx, cfg, 0, &prev_pid) != 0 ||
        tp_read(ctx, cfg, 1, &prev_state) != 0 ||
        tp_read(ctx, cfg, 2, &prev_prio) != 0 ||
        tp_read(ctx, cfg, 3, &next_pid) != 0 ||
        tp_read(ctx, cfg, 4, &next_prio) != 0)
        return 0;

    const __u32 prev = (__u32)prev_pid;
    const __u32 next = (__u32)next_pid;
    if (!is_target_tid(prev) && !is_target_tid(next))
        return 0;

    __u64 id = bpf_get_current_pid_tgid();
    emit_kernel(CG_KEV_SCHED_SWITCH, CG_KCAT_SCHED,
                CG_KF_DIRECT, prev, (__u32)(id >> 32), next, 0,
                prev_state, prev_prio, next_prio, 0, 0, 0, 0, 0);
    return 0;
}

static __always_inline int emit_wakeup(void *ctx, __u16 kind)
{
    struct cg_tp_config *cfg = tp_config_for(kind);
    __u64 pid = 0, prio = 0, target_cpu = 0;
    if (tp_read(ctx, cfg, 0, &pid) != 0 ||
        tp_read_opt(ctx, cfg, 1, &prio) != 0 ||
        tp_read_opt(ctx, cfg, 2, &target_cpu) != 0)
        return 0;

    const __u32 target = (__u32)pid;
    const __u64 current = bpf_get_current_pid_tgid();
    const __u32 waker = (__u32)current;
    if (!is_target_tid(target) && !is_target_tid(waker))
        return 0;

    emit_kernel(kind, CG_KCAT_SCHED, CG_KF_DIRECT, target, 0, waker,
                (__u32)(current >> 32), prio, 0, target_cpu,
                0, 0, 0, 0, 0);
    return 0;
}

SEC("tp/sched/sched_wakeup")
int cg_sched_wakeup(void *ctx)
{
    return emit_wakeup(ctx, CG_KEV_SCHED_WAKEUP);
}

SEC("tp/sched/sched_waking")
int cg_sched_waking(void *ctx)
{
    return emit_wakeup(ctx, CG_KEV_SCHED_WAKING);
}

SEC("tp/sched/sched_wakeup_new")
int cg_sched_wakeup_new(void *ctx)
{
    return emit_wakeup(ctx, CG_KEV_SCHED_WAKEUP_NEW);
}

SEC("tp/sched/sched_migrate_task")
int cg_sched_migrate(void *ctx)
{
    struct cg_tp_config *cfg = tp_config_for(CG_KEV_SCHED_MIGRATE);
    __u64 pid = 0, prio = 0, orig_cpu = 0, dest_cpu = 0;
    if (tp_read(ctx, cfg, 0, &pid) != 0 ||
        tp_read_opt(ctx, cfg, 1, &prio) != 0 ||
        tp_read_opt(ctx, cfg, 2, &orig_cpu) != 0 ||
        tp_read_opt(ctx, cfg, 3, &dest_cpu) != 0)
        return 0;

    const __u32 target = (__u32)pid;
    if (!is_target_tid(target))
        return 0;

    emit_kernel(CG_KEV_SCHED_MIGRATE, CG_KCAT_SCHED, CG_KF_DIRECT,
                target, 0, 0, 0, prio, orig_cpu, dest_cpu, 0, 0, 0, 0, 0);
    return 0;
}

SEC("tp/sched/sched_process_fork")
int cg_proc_fork(void *ctx)
{
    struct cg_tp_config *cfg = tp_config_for(CG_KEV_PROC_FORK);
    __u64 parent = 0, child = 0;
    if (tp_read(ctx, cfg, 0, &parent) != 0 ||
        tp_read(ctx, cfg, 1, &child) != 0)
        return 0;

    if (!is_target_tid((__u32)parent))
        return 0;

    emit_kernel(CG_KEV_PROC_FORK, CG_KCAT_SCHED, CG_KF_DIRECT,
                (__u32)parent, 0, (__u32)child, 0, parent, child,
                0, 0, 0, 0, 0, 0);
    return 0;
}

SEC("tp/sched/sched_process_exit")
int cg_proc_exit(void *ctx)
{
    struct cg_tp_config *cfg = tp_config_for(CG_KEV_PROC_EXIT);
    __u64 pid = 0, prio = 0;
    if (tp_read(ctx, cfg, 0, &pid) != 0 ||
        tp_read_opt(ctx, cfg, 1, &prio) != 0)
        return 0;

    const __u32 target = (__u32)pid;
    if (!is_target_tid(target))
        return 0;

    emit_kernel(CG_KEV_PROC_EXIT, CG_KCAT_SCHED, CG_KF_DIRECT,
                target, 0, 0, 0, prio, 0, 0, 0, 0, 0, 0, 0);
    return 0;
}

#endif /* CALLGRAPH_KERNEL_SCHED_BPF_H */
