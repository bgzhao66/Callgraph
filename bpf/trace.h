/* Shared event layout between the BPF program and user space. */
#ifndef CALLGRAPH_TRACE_H
#define CALLGRAPH_TRACE_H

#include <linux/types.h>

#define CG_EVENT_ENTER 1
#define CG_EVENT_EXIT  2

struct cg_event {
    __u64 ts;
    __u64 func_id;
    __u32 tgid;
    __u32 tid;
    __u8  type;
    __u8  pad[7];
};

#endif /* CALLGRAPH_TRACE_H */
