/* Shared kernel-event layout between the kernel BPF program and user space. */
#ifndef CALLGRAPH_KERNEL_EVENT_H
#define CALLGRAPH_KERNEL_EVENT_H

#include <linux/types.h>

#define CG_KERNEL_EVENT_VERSION 1

enum cg_kernel_category {
    CG_KCAT_SCHED = 1,
    CG_KCAT_FUTEX = 2,
    CG_KCAT_IO = 3,
    CG_KCAT_BLOCK = 4,
    CG_KCAT_NET = 5,
    CG_KCAT_MM = 6,
    CG_KCAT_PMU = 7,
    CG_KCAT_IRQ = 8,
    CG_KCAT_WORK = 9,
};

enum cg_kernel_kind {
    CG_KEV_SCHED_SWITCH = 1,
    CG_KEV_SCHED_WAKEUP,
    CG_KEV_SCHED_WAKING,
    CG_KEV_SCHED_WAKEUP_NEW,
    CG_KEV_SCHED_MIGRATE,
    CG_KEV_PROC_FORK,
    CG_KEV_PROC_EXIT,

    CG_KEV_FUTEX_ENTER,
    CG_KEV_FUTEX_EXIT,

    CG_KEV_READ_ENTER,
    CG_KEV_READ_EXIT,
    CG_KEV_WRITE_ENTER,
    CG_KEV_WRITE_EXIT,
    CG_KEV_PREAD64_ENTER,
    CG_KEV_PREAD64_EXIT,
    CG_KEV_PWRITE64_ENTER,
    CG_KEV_PWRITE64_EXIT,
    CG_KEV_FSYNC_ENTER,
    CG_KEV_FSYNC_EXIT,
    CG_KEV_FDATASYNC_ENTER,
    CG_KEV_FDATASYNC_EXIT,
    CG_KEV_OPENAT_ENTER,
    CG_KEV_OPENAT_EXIT,
    CG_KEV_CLOSE_ENTER,
    CG_KEV_CLOSE_EXIT,
    CG_KEV_SYNC_FILE_RANGE_ENTER,
    CG_KEV_SYNC_FILE_RANGE_EXIT,

    CG_KEV_BLOCK_INSERT,
    CG_KEV_BLOCK_ISSUE,
    CG_KEV_BLOCK_COMPLETE,
    CG_KEV_BLOCK_REQUEUE,
    CG_KEV_BLOCK_ERROR,
};

#define CG_KF_BEGIN      0x01
#define CG_KF_END        0x02
#define CG_KF_DIRECT     0x04
#define CG_KF_CAUSAL     0x08
#define CG_KF_GLOBAL     0x10
#define CG_KF_PARTIAL    0x20
#define CG_KF_INCOMPLETE 0x40
#define CG_KF_LOST       0x80

/* Maximum fields captured from one tracepoint. */
#define CG_TP_MAX_FIELDS 8

struct cg_tp_field {
    __u16 offset;
    __u8 size;
    __u8 pad;
};

struct cg_tp_config {
    struct cg_tp_field field[CG_TP_MAX_FIELDS];
};

struct cg_kernel_config {
    __u32 system_wide;
    __u32 families;
};

/*
 * Fixed 96-byte record.  a..h are event-specific; see
 * docs/kernel-event-design.md.  Keeping one fixed layout lets BPF reserve the
 * record without a union whose layout could drift between BPF and C++.
 */
struct cg_kernel_event {
    __u64 ts;
    __u32 tid;
    __u32 tgid;
    __u32 peer_tid;
    __u32 peer_tgid;
    __u32 cpu;
    __u16 kind;
    __u8 category;
    __u8 flags;
    __u64 a;
    __u64 b;
    __u64 c;
    __u64 d;
    __u64 e;
    __u64 f;
    __u64 g;
    __u64 h;
};

#endif /* CALLGRAPH_KERNEL_EVENT_H */
