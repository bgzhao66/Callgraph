#pragma once

#include "trace.h"

namespace callgraph {

using TraceEvent = cg_event;

constexpr uint8_t kEventEnter = CG_EVENT_ENTER;
constexpr uint8_t kEventExit = CG_EVENT_EXIT;

static_assert(sizeof(TraceEvent) == 136, "unexpected event size");

}  // namespace callgraph
