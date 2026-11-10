#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#include "trace.h"

/*
 * x86-64 struct pt_regs, in the order the kernel places it on the stack for
 * a uprobe.  bpf_tracing.h's PT_REGS_PARM* macros need either vmlinux.h or
 * __KERNEL__, neither of which we use here, so define the layout directly.
 */
#ifdef CALLGRAPH_BPF_X86_64
struct cg_pt_regs {
    __u64 r15;
    __u64 r14;
    __u64 r13;
    __u64 r12;
    __u64 rbp;
    __u64 rbx;
    __u64 r11;
    __u64 r10;
    __u64 r9;
    __u64 r8;
    __u64 rax;
    __u64 rcx;
    __u64 rdx;
    __u64 rsi;
    __u64 rdi;
    __u64 orig_ax;
    __u64 rip;
    __u64 cs;
    __u64 flags;
    __u64 rsp;
    __u64 ss;
};
#endif

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

/* Set to 1 by user space when --args is enabled. */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u8);
} config SEC(".maps");

static __always_inline void capture_arguments(void *ctx, struct cg_event *e)
{
#ifdef CALLGRAPH_BPF_X86_64
    const struct cg_pt_regs *regs = (const struct cg_pt_regs *)ctx;
    __u64 stack[CG_MAX_STACK_ARGS];

    e->args[0] = regs->rdi;
    e->args[1] = regs->rsi;
    e->args[2] = regs->rdx;
    e->args[3] = regs->rcx;
    e->args[4] = regs->r8;
    e->args[5] = regs->r9;

    /*
     * At the first instruction of a function, rsp points at the return
     * address, so stack-passed arguments start at rsp + 8.  Reading into a
     * local array first keeps the verifier happy about ring-buffer memory.
     */
    __builtin_memset(stack, 0, sizeof(stack));
    if (regs->rsp &&
        bpf_probe_read_user(stack, sizeof(stack),
                            (const void *)(regs->rsp + 8)) == 0)
        __builtin_memcpy(e->stack, stack, sizeof(stack));
#else
    (void)ctx;
    (void)e;
#endif
}

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
    __builtin_memset(e->args, 0, sizeof(e->args));
    __builtin_memset(e->stack, 0, sizeof(e->stack));

    if (type == CG_EVENT_ENTER) {
        __u8 *capture = bpf_map_lookup_elem(&config, &key);
        if (capture && *capture)
            capture_arguments(ctx, e);
    }

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
