/* Shared event layout between the BPF program and user space. */
#ifndef CALLGRAPH_TRACE_H
#define CALLGRAPH_TRACE_H

#include <linux/types.h>

#define CG_EVENT_ENTER 1
#define CG_EVENT_EXIT  2

/* Number of integer/pointer arguments passed in registers (SysV x86-64). */
#define CG_MAX_GP_ARGS 6
/* Number of 8-byte words captured from the user stack at rsp + 8. */
#define CG_MAX_STACK_ARGS 6

struct cg_event {
    __u64 ts;
    __u64 func_id;
    __u32 tgid;
    __u32 tid;
    __u8  type;
    __u8  pad[7];

    /* Captured on entry; zeroed on exit. */
    __u64 args[CG_MAX_GP_ARGS];
    __u64 stack[CG_MAX_STACK_ARGS];
};

#endif /* CALLGRAPH_TRACE_H */
