#pragma once

#include <cstdint>

#include <kernel_event.h>

namespace callgraph {

using KernelEvent = cg_kernel_event;

constexpr uint8_t kKernelCatSched = CG_KCAT_SCHED;
constexpr uint8_t kKernelCatFutex = CG_KCAT_FUTEX;
constexpr uint8_t kKernelCatIo = CG_KCAT_IO;
constexpr uint8_t kKernelCatBlock = CG_KCAT_BLOCK;
constexpr uint8_t kKernelCatNet = CG_KCAT_NET;
constexpr uint8_t kKernelCatMm = CG_KCAT_MM;

constexpr uint16_t kKernelSchedSwitch = CG_KEV_SCHED_SWITCH;
constexpr uint16_t kKernelSchedWakeup = CG_KEV_SCHED_WAKEUP;
constexpr uint16_t kKernelSchedWaking = CG_KEV_SCHED_WAKING;
constexpr uint16_t kKernelSchedWakeupNew = CG_KEV_SCHED_WAKEUP_NEW;
constexpr uint16_t kKernelSchedMigrate = CG_KEV_SCHED_MIGRATE;
constexpr uint16_t kKernelProcFork = CG_KEV_PROC_FORK;
constexpr uint16_t kKernelProcExit = CG_KEV_PROC_EXIT;
constexpr uint16_t kKernelFutexEnter = CG_KEV_FUTEX_ENTER;
constexpr uint16_t kKernelFutexExit = CG_KEV_FUTEX_EXIT;
constexpr uint16_t kKernelPageFaultUser = CG_KEV_PAGE_FAULT_USER;
constexpr uint16_t kKernelPageFaultKernel = CG_KEV_PAGE_FAULT_KERNEL;
constexpr uint16_t kKernelDirectReclaimBegin = CG_KEV_DIRECT_RECLAIM_BEGIN;
constexpr uint16_t kKernelDirectReclaimEnd = CG_KEV_DIRECT_RECLAIM_END;
constexpr uint16_t kKernelTcpRetransmit = CG_KEV_TCP_RETRANSMIT;

constexpr int kKernelDepthNone = -1;
constexpr int kKernelDepthGlobal = -2;

const char* kernel_category_name(uint8_t category);
const char* kernel_kind_name(uint16_t kind);

// Returns the event name for a syscall enter/exit kind (e.g. "read_begin").
const char* kernel_io_event_name(uint16_t kind);
bool kernel_is_io_enter(uint16_t kind);
bool kernel_is_io_exit(uint16_t kind);

const char* kernel_net_event_name(uint16_t kind);
bool kernel_is_net_enter(uint16_t kind);
bool kernel_is_net_exit(uint16_t kind);

static_assert(sizeof(KernelEvent) == 96, "unexpected kernel event size");

}  // namespace callgraph
