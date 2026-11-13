#pragma once

#include <array>
#include <cstdint>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "callgraph/event.h"
#include "callgraph/kernel_event.h"

namespace callgraph {

class CallStack;
class Output;

enum class BlockReason : uint8_t {
    None = 0,
    Futex,
    Io,
    Net,
    Memory,
    Uninterruptible,
    Sleep,
    Other,
};

constexpr size_t kBlockReasonCount = 8;

const char* block_reason_name(BlockReason reason);

struct KernelCounters {
    uint64_t cpu_ns = 0;
    uint64_t runnable_ns = 0;
    std::array<uint64_t, kBlockReasonCount> blocked_ns = {};
    uint64_t switches = 0;
    uint64_t migrations = 0;
    uint64_t kernel_events = 0;
    bool partial = false;

    uint64_t blocked_total() const;
};

struct KernelFunctionStats {
    uint32_t tid = 0;
    uint32_t depth = 0;
    uint64_t function_id = 0;
    KernelCounters counters;
};

// Reconstructs per-TID execution state from kernel events and attributes
// elapsed time to the user frame that was on top at each event boundary.
class KernelTimeline {
public:
    KernelTimeline(Output& output, int max_depth, bool verbose);

    void set_target_tids(const std::vector<uint32_t>& tids);
    void add_target_tid(uint32_t tid);
    bool is_target(uint32_t tid) const;

    // Must be called before CallStack applies the event: the interval that
    // ends at event.ts belongs to the old top frame.
    void on_function_event(const TraceEvent& event, const CallStack& stack);
    void on_kernel_event(const KernelEvent& event, const CallStack& stack);
    void finish(uint64_t stop_ts, const CallStack& stack);

    std::string format_report(const std::vector<std::string>& names) const;

    uint64_t kernel_events() const { return kernel_events_; }
    uint64_t out_of_order() const { return out_of_order_; }

private:
    enum class CpuState { Unknown, OnCpu, Blocked, Runnable };

    struct PendingOp {
        uint16_t kind = 0;
        uint64_t ts = 0;
        uint64_t id = 0;
        uint64_t fd = 0;
        uint32_t nr = 0;
        uint32_t op = 0;
    };

    struct ThreadRuntime {
        CpuState state = CpuState::Unknown;
        uint64_t last_ns = 0;
        bool have_last = false;
        uint64_t offcpu_since_ns = 0;
        uint64_t runnable_since_ns = 0;
        uint64_t pending_switch_id = 0;
        uint32_t prev_state = 0;
        BlockReason reason = BlockReason::Other;
        std::vector<PendingOp> ops;
        bool partial = false;
        uint64_t out_of_order = 0;
    };

    struct StatKey {
        uint32_t tid = 0;
        uint32_t depth = 0;
        uint64_t function_id = 0;

        bool operator==(const StatKey& other) const
        {
            return tid == other.tid && depth == other.depth &&
                   function_id == other.function_id;
        }
    };

    struct StatKeyHash {
        size_t operator()(const StatKey& key) const noexcept;
    };

    struct BlockKey {
        uint32_t dev = 0;
        uint64_t sector = 0;
        uint32_t nr_sector = 0;

        bool operator==(const BlockKey& other) const
        {
            return dev == other.dev && sector == other.sector &&
                   nr_sector == other.nr_sector;
        }
    };

    struct BlockKeyHash {
        size_t operator()(const BlockKey& key) const noexcept;
    };

    struct BlockPending {
        uint64_t insert_ns = 0;
        uint64_t issue_ns = 0;
        uint64_t id = 0;
        bool issued = false;
    };

    void account_until(uint32_t tid, uint64_t ts, const CallStack& stack);
    void add_account(uint32_t tid, uint32_t depth, uint64_t function_id,
                     uint64_t delta_ns);
    BlockReason classify_block(const ThreadRuntime& thread) const;
    void on_sched_switch(const KernelEvent& event, const CallStack& stack);
    void on_sched_wakeup(const KernelEvent& event, const CallStack& stack);
    void on_futex(const KernelEvent& event, const CallStack& stack);
    void on_io(const KernelEvent& event, const CallStack& stack);
    void on_block(const KernelEvent& event);
    void emit_event(const KernelEvent& event, int depth,
                    const std::string& name, const std::string& attrs);
    uint64_t next_id();
    std::string state_name(uint32_t state) const;

    Output& output_;
    int max_depth_;
    bool verbose_;
    uint64_t next_id_ = 1;
    uint64_t kernel_events_ = 0;
    uint64_t out_of_order_ = 0;
    std::unordered_set<uint32_t> targets_;
    std::unordered_set<uint32_t> exited_;
    std::unordered_map<uint32_t, ThreadRuntime> threads_;
    std::unordered_map<uint32_t, KernelCounters> thread_counters_;
    std::unordered_map<StatKey, KernelCounters, StatKeyHash> function_counters_;
    std::unordered_map<BlockKey, BlockPending, BlockKeyHash> block_pending_;
};

std::string format_kernel_report(const KernelTimeline& timeline,
                                 const std::vector<std::string>& names);

}  // namespace callgraph
