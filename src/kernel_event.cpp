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
    default:
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

}  // namespace callgraph
