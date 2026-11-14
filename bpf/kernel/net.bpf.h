#ifndef CALLGRAPH_KERNEL_NET_BPF_H
#define CALLGRAPH_KERNEL_NET_BPF_H

#include "kernel/common.bpf.h"
#include "kernel/syscall.bpf.h"

CG_DEFINE_SYS_ENTER(socket, CG_KEV_NET_SOCKET_ENTER, CG_KCAT_NET)
CG_DEFINE_SYS_EXIT(socket, CG_KEV_NET_SOCKET_EXIT, CG_KCAT_NET)

CG_DEFINE_SYS_ENTER(connect, CG_KEV_NET_CONNECT_ENTER, CG_KCAT_NET)
CG_DEFINE_SYS_EXIT(connect, CG_KEV_NET_CONNECT_EXIT, CG_KCAT_NET)

CG_DEFINE_SYS_ENTER(accept4, CG_KEV_NET_ACCEPT4_ENTER, CG_KCAT_NET)
CG_DEFINE_SYS_EXIT(accept4, CG_KEV_NET_ACCEPT4_EXIT, CG_KCAT_NET)

CG_DEFINE_SYS_ENTER(sendto, CG_KEV_NET_SENDTO_ENTER, CG_KCAT_NET)
CG_DEFINE_SYS_EXIT(sendto, CG_KEV_NET_SENDTO_EXIT, CG_KCAT_NET)

CG_DEFINE_SYS_ENTER(recvfrom, CG_KEV_NET_RECVFROM_ENTER, CG_KCAT_NET)
CG_DEFINE_SYS_EXIT(recvfrom, CG_KEV_NET_RECVFROM_EXIT, CG_KCAT_NET)

CG_DEFINE_SYS_ENTER(sendmsg, CG_KEV_NET_SENDMSG_ENTER, CG_KCAT_NET)
CG_DEFINE_SYS_EXIT(sendmsg, CG_KEV_NET_SENDMSG_EXIT, CG_KCAT_NET)

CG_DEFINE_SYS_ENTER(recvmsg, CG_KEV_NET_RECVMSG_ENTER, CG_KCAT_NET)
CG_DEFINE_SYS_EXIT(recvmsg, CG_KEV_NET_RECVMSG_EXIT, CG_KCAT_NET)

CG_DEFINE_SYS_ENTER(epoll_wait, CG_KEV_NET_EPOLL_WAIT_ENTER, CG_KCAT_NET)
CG_DEFINE_SYS_EXIT(epoll_wait, CG_KEV_NET_EPOLL_WAIT_EXIT, CG_KCAT_NET)

CG_DEFINE_SYS_ENTER(poll, CG_KEV_NET_POLL_ENTER, CG_KCAT_NET)
CG_DEFINE_SYS_EXIT(poll, CG_KEV_NET_POLL_EXIT, CG_KCAT_NET)

// TCP retransmits run in softirq or the socket owner's context and carry no
// reliable target TID, so they are global records.  They are opt-in with
// --network and reported in the global section, never charged to a function.
SEC("tp/tcp/tcp_retransmit_skb")
int cg_tcp_retransmit(void *ctx)
{
    struct cg_tp_config *cfg = tp_config_for(CG_KEV_TCP_RETRANSMIT);
    __u64 state = 0, sport = 0, dport = 0, family = 0;
    __u64 saddr = 0, daddr = 0, err = 0;
    if (tp_read(ctx, cfg, 0, &state) != 0 ||
        tp_read(ctx, cfg, 1, &sport) != 0 ||
        tp_read(ctx, cfg, 2, &dport) != 0 ||
        tp_read(ctx, cfg, 3, &family) != 0 ||
        tp_read_opt(ctx, cfg, 4, &saddr) != 0 ||
        tp_read_opt(ctx, cfg, 5, &daddr) != 0 ||
        tp_read_opt(ctx, cfg, 6, &err) != 0)
        return 0;

    emit_kernel(CG_KEV_TCP_RETRANSMIT, CG_KCAT_NET, CG_KF_GLOBAL, 0, 0, 0, 0,
                state, sport, dport, family, saddr, daddr, err, 0);
    return 0;
}

#endif /* CALLGRAPH_KERNEL_NET_BPF_H */
