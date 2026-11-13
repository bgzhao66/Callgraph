#ifndef CALLGRAPH_KERNEL_BLOCK_BPF_H
#define CALLGRAPH_KERNEL_BLOCK_BPF_H

#include "kernel/common.bpf.h"

#define CG_DEFINE_BLOCK(name, kind, nfields, last_is_error)                    \
    SEC("tp/block/" #name)                                                     \
    int cg_block_##name(void *ctx)                                             \
    {                                                                          \
        struct cg_tp_config *cfg = tp_config_for(kind);                        \
        __u64 dev = 0, sector = 0, nr_sector = 0, extra = 0;                   \
        if (tp_read(ctx, cfg, 0, &dev) != 0 ||                                 \
            tp_read(ctx, cfg, 1, &sector) != 0 ||                              \
            tp_read_opt(ctx, cfg, 2, &nr_sector) != 0 ||                       \
            (nfields > 3 && tp_read_opt(ctx, cfg, 3, &extra) != 0))            \
            return 0;                                                          \
        emit_kernel(kind, CG_KCAT_BLOCK, CG_KF_GLOBAL, 0, 0, 0, 0,            \
                    dev, sector, nr_sector,                                    \
                    last_is_error ? 0 : extra,                                 \
                    last_is_error ? extra : 0, 0, 0, 0);                       \
        return 0;                                                              \
    }

CG_DEFINE_BLOCK(block_rq_insert, CG_KEV_BLOCK_INSERT, 4, 0)
CG_DEFINE_BLOCK(block_rq_issue, CG_KEV_BLOCK_ISSUE, 4, 0)
CG_DEFINE_BLOCK(block_rq_complete, CG_KEV_BLOCK_COMPLETE, 4, 1)
CG_DEFINE_BLOCK(block_rq_requeue, CG_KEV_BLOCK_REQUEUE, 3, 0)
CG_DEFINE_BLOCK(block_rq_error, CG_KEV_BLOCK_ERROR, 4, 1)

#endif /* CALLGRAPH_KERNEL_BLOCK_BPF_H */
