#include "callgraph/kernel_event.h"

namespace callgraph {

const char* kernel_category_name(uint8_t category)
{
    switch (category) {
    case CG_KCAT_SCHED:
        return "SCHED";
    case CG_KCAT_FUTEX:
        return "FUTEX";
    case CG_KCAT_IO:
        return "IO";
    case CG_KCAT_BLOCK:
        return "BLOCK";
    case CG_KCAT_NET:
        return "NET";
    case CG_KCAT_MM:
        return "MM";
    case CG_KCAT_PMU:
        return "PMU";
    case CG_KCAT_IRQ:
        return "IRQ";
    case CG_KCAT_WORK:
        return "WORK";
    }
    return "UNKNOWN";
}

const char* kernel_kind_name(uint16_t kind)
{
    switch (kind) {
    case CG_KEV_SCHED_SWITCH:
        return "switch";
    case CG_KEV_SCHED_WAKEUP:
        return "wakeup";
    case CG_KEV_SCHED_WAKING:
        return "waking";
    case CG_KEV_SCHED_WAKEUP_NEW:
        return "wakeup_new";
    case CG_KEV_SCHED_MIGRATE:
        return "migrate";
    case CG_KEV_PROC_FORK:
        return "fork";
    case CG_KEV_PROC_EXIT:
        return "exit";
    case CG_KEV_FUTEX_ENTER:
        return "futex_begin";
    case CG_KEV_FUTEX_EXIT:
        return "futex_end";
    case CG_KEV_BLOCK_INSERT:
        return "rq_insert";
    case CG_KEV_BLOCK_ISSUE:
        return "rq_issue";
    case CG_KEV_BLOCK_COMPLETE:
        return "rq_complete";
    case CG_KEV_BLOCK_REQUEUE:
        return "rq_requeue";
    case CG_KEV_BLOCK_ERROR:
        return "rq_error";
    case CG_KEV_PAGE_FAULT_USER:
    case CG_KEV_PAGE_FAULT_KERNEL:
        return "page_fault";
    case CG_KEV_DIRECT_RECLAIM_BEGIN:
        return "direct_reclaim_begin";
    case CG_KEV_DIRECT_RECLAIM_END:
        return "direct_reclaim_end";
    case CG_KEV_TCP_RETRANSMIT:
        return "tcp_retransmit";
    default:
        if (kind >= CG_KEV_NET_SOCKET_ENTER &&
            kind <= CG_KEV_NET_POLL_EXIT)
            return kernel_net_event_name(kind);
        return kernel_io_event_name(kind);
    }
}

const char* kernel_io_event_name(uint16_t kind)
{
    switch (kind) {
    case CG_KEV_READ_ENTER:
        return "read_begin";
    case CG_KEV_READ_EXIT:
        return "read_end";
    case CG_KEV_WRITE_ENTER:
        return "write_begin";
    case CG_KEV_WRITE_EXIT:
        return "write_end";
    case CG_KEV_PREAD64_ENTER:
        return "pread64_begin";
    case CG_KEV_PREAD64_EXIT:
        return "pread64_end";
    case CG_KEV_PWRITE64_ENTER:
        return "pwrite64_begin";
    case CG_KEV_PWRITE64_EXIT:
        return "pwrite64_end";
    case CG_KEV_FSYNC_ENTER:
        return "fsync_begin";
    case CG_KEV_FSYNC_EXIT:
        return "fsync_end";
    case CG_KEV_FDATASYNC_ENTER:
        return "fdatasync_begin";
    case CG_KEV_FDATASYNC_EXIT:
        return "fdatasync_end";
    case CG_KEV_OPENAT_ENTER:
        return "openat_begin";
    case CG_KEV_OPENAT_EXIT:
        return "openat_end";
    case CG_KEV_CLOSE_ENTER:
        return "close_begin";
    case CG_KEV_CLOSE_EXIT:
        return "close_end";
    case CG_KEV_SYNC_FILE_RANGE_ENTER:
        return "sync_file_range_begin";
    case CG_KEV_SYNC_FILE_RANGE_EXIT:
        return "sync_file_range_end";
    default:
        return "unknown";
    }
}

bool kernel_is_io_enter(uint16_t kind)
{
    switch (kind) {
    case CG_KEV_READ_ENTER:
    case CG_KEV_WRITE_ENTER:
    case CG_KEV_PREAD64_ENTER:
    case CG_KEV_PWRITE64_ENTER:
    case CG_KEV_FSYNC_ENTER:
    case CG_KEV_FDATASYNC_ENTER:
    case CG_KEV_OPENAT_ENTER:
    case CG_KEV_CLOSE_ENTER:
    case CG_KEV_SYNC_FILE_RANGE_ENTER:
        return true;
    default:
        return false;
    }
}

bool kernel_is_io_exit(uint16_t kind)
{
    return kernel_is_io_enter(static_cast<uint16_t>(kind - 1));
}

const char* kernel_net_event_name(uint16_t kind)
{
    switch (kind) {
    case CG_KEV_NET_SOCKET_ENTER:
        return "socket_begin";
    case CG_KEV_NET_SOCKET_EXIT:
        return "socket_end";
    case CG_KEV_NET_CONNECT_ENTER:
        return "connect_begin";
    case CG_KEV_NET_CONNECT_EXIT:
        return "connect_end";
    case CG_KEV_NET_ACCEPT4_ENTER:
        return "accept4_begin";
    case CG_KEV_NET_ACCEPT4_EXIT:
        return "accept4_end";
    case CG_KEV_NET_SENDTO_ENTER:
        return "sendto_begin";
    case CG_KEV_NET_SENDTO_EXIT:
        return "sendto_end";
    case CG_KEV_NET_RECVFROM_ENTER:
        return "recvfrom_begin";
    case CG_KEV_NET_RECVFROM_EXIT:
        return "recvfrom_end";
    case CG_KEV_NET_SENDMSG_ENTER:
        return "sendmsg_begin";
    case CG_KEV_NET_SENDMSG_EXIT:
        return "sendmsg_end";
    case CG_KEV_NET_RECVMSG_ENTER:
        return "recvmsg_begin";
    case CG_KEV_NET_RECVMSG_EXIT:
        return "recvmsg_end";
    case CG_KEV_NET_EPOLL_WAIT_ENTER:
        return "epoll_wait_begin";
    case CG_KEV_NET_EPOLL_WAIT_EXIT:
        return "epoll_wait_end";
    case CG_KEV_NET_POLL_ENTER:
        return "poll_begin";
    case CG_KEV_NET_POLL_EXIT:
        return "poll_end";
    default:
        return "unknown";
    }
}

bool kernel_is_net_enter(uint16_t kind)
{
    switch (kind) {
    case CG_KEV_NET_SOCKET_ENTER:
    case CG_KEV_NET_CONNECT_ENTER:
    case CG_KEV_NET_ACCEPT4_ENTER:
    case CG_KEV_NET_SENDTO_ENTER:
    case CG_KEV_NET_RECVFROM_ENTER:
    case CG_KEV_NET_SENDMSG_ENTER:
    case CG_KEV_NET_RECVMSG_ENTER:
    case CG_KEV_NET_EPOLL_WAIT_ENTER:
    case CG_KEV_NET_POLL_ENTER:
        return true;
    default:
        return false;
    }
}

bool kernel_is_net_exit(uint16_t kind)
{
    return kernel_is_net_enter(static_cast<uint16_t>(kind - 1));
}

}  // namespace callgraph
