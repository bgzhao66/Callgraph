#ifndef CALLGRAPH_KERNEL_SYSCALL_BPF_H
#define CALLGRAPH_KERNEL_SYSCALL_BPF_H

#include "kernel/common.bpf.h"

#define CG_DEFINE_SYS_ENTER(name, kind, category)                              \
    SEC("tp/syscalls/sys_enter_" #name)                                        \
    int cg_sys_enter_##name(void *ctx)                                         \
    {                                                                          \
        struct cg_tp_config *cfg = tp_config_for(kind);                        \
        __u64 v[7] = {};                                                       \
        if (tp_read(ctx, cfg, 0, &v[0]) != 0 ||                                \
            tp_read_opt(ctx, cfg, 1, &v[1]) != 0 ||                            \
            tp_read_opt(ctx, cfg, 2, &v[2]) != 0 ||                            \
            tp_read_opt(ctx, cfg, 3, &v[3]) != 0 ||                            \
            tp_read_opt(ctx, cfg, 4, &v[4]) != 0 ||                            \
            tp_read_opt(ctx, cfg, 5, &v[5]) != 0 ||                            \
            tp_read_opt(ctx, cfg, 6, &v[6]) != 0)                              \
            return 0;                                                          \
        const __u64 current = bpf_get_current_pid_tgid();                       \
        const __u32 tid = (__u32)current;                                       \
        if (!is_target_tid(tid))                                                \
            return 0;                                                          \
        emit_kernel(kind, category, CG_KF_DIRECT | CG_KF_BEGIN, tid,          \
                    (__u32)(current >> 32), 0, 0, v[0], v[1], v[2], v[3],      \
                    v[4], v[5], v[6], 0);                                      \
        return 0;                                                              \
    }

#define CG_DEFINE_SYS_EXIT(name, kind, category)                               \
    SEC("tp/syscalls/sys_exit_" #name)                                         \
    int cg_sys_exit_##name(void *ctx)                                          \
    {                                                                          \
        struct cg_tp_config *cfg = tp_config_for(kind);                        \
        __u64 nr = 0, ret = 0;                                                 \
        if (tp_read(ctx, cfg, 0, &nr) != 0 ||                                  \
            tp_read(ctx, cfg, 1, &ret) != 0)                                   \
            return 0;                                                          \
        const __u64 current = bpf_get_current_pid_tgid();                       \
        const __u32 tid = (__u32)current;                                       \
        if (!is_target_tid(tid))                                                \
            return 0;                                                          \
        emit_kernel(kind, category, CG_KF_DIRECT | CG_KF_END, tid,            \
                    (__u32)(current >> 32), 0, 0, nr, ret, 0, 0, 0, 0, 0, 0);  \
        return 0;                                                              \
    }

CG_DEFINE_SYS_ENTER(futex, CG_KEV_FUTEX_ENTER, CG_KCAT_FUTEX)
CG_DEFINE_SYS_EXIT(futex, CG_KEV_FUTEX_EXIT, CG_KCAT_FUTEX)

CG_DEFINE_SYS_ENTER(read, CG_KEV_READ_ENTER, CG_KCAT_IO)
CG_DEFINE_SYS_EXIT(read, CG_KEV_READ_EXIT, CG_KCAT_IO)
CG_DEFINE_SYS_ENTER(write, CG_KEV_WRITE_ENTER, CG_KCAT_IO)
CG_DEFINE_SYS_EXIT(write, CG_KEV_WRITE_EXIT, CG_KCAT_IO)
CG_DEFINE_SYS_ENTER(pread64, CG_KEV_PREAD64_ENTER, CG_KCAT_IO)
CG_DEFINE_SYS_EXIT(pread64, CG_KEV_PREAD64_EXIT, CG_KCAT_IO)
CG_DEFINE_SYS_ENTER(pwrite64, CG_KEV_PWRITE64_ENTER, CG_KCAT_IO)
CG_DEFINE_SYS_EXIT(pwrite64, CG_KEV_PWRITE64_EXIT, CG_KCAT_IO)
CG_DEFINE_SYS_ENTER(fsync, CG_KEV_FSYNC_ENTER, CG_KCAT_IO)
CG_DEFINE_SYS_EXIT(fsync, CG_KEV_FSYNC_EXIT, CG_KCAT_IO)
CG_DEFINE_SYS_ENTER(fdatasync, CG_KEV_FDATASYNC_ENTER, CG_KCAT_IO)
CG_DEFINE_SYS_EXIT(fdatasync, CG_KEV_FDATASYNC_EXIT, CG_KCAT_IO)
CG_DEFINE_SYS_ENTER(openat, CG_KEV_OPENAT_ENTER, CG_KCAT_IO)
CG_DEFINE_SYS_EXIT(openat, CG_KEV_OPENAT_EXIT, CG_KCAT_IO)
CG_DEFINE_SYS_ENTER(close, CG_KEV_CLOSE_ENTER, CG_KCAT_IO)
CG_DEFINE_SYS_EXIT(close, CG_KEV_CLOSE_EXIT, CG_KCAT_IO)
CG_DEFINE_SYS_ENTER(sync_file_range, CG_KEV_SYNC_FILE_RANGE_ENTER, CG_KCAT_IO)
CG_DEFINE_SYS_EXIT(sync_file_range, CG_KEV_SYNC_FILE_RANGE_EXIT, CG_KCAT_IO)

#endif /* CALLGRAPH_KERNEL_SYSCALL_BPF_H */
