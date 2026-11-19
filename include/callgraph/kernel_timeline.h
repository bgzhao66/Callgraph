#pragma once

#include <cstdint>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "callgraph/event.h"
#include "callgraph/kernel_event.h"
#include "callgraph/kernel_histogram.h"
#include "callgraph/kernel_span.h"
#include "callgraph/pmu.h"

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

const char* block_reason_name(BlockReason reason);

// Reconstructs per-TID execution state from kernel events and attributes
// intervals to the user frame that was on top at each event boundary.
class KernelTimeline {
public:
    KernelTimeline(Output& output, int max_depth, bool verbose);

    void set_target_tids(const std::vector<uint32_t>& tids);
    void add_target_tid(uint32_t tid);
    bool is_target(uint32_t tid) const;
    void set_kernel_span_sink(KernelSpanSink* sink) { span_sink_ = sink; }
    // Enables per-root kernel latency histograms.  Off by default so text-only
    // runs do not build call paths or allocate histogram entries.
    void set_collect_histograms(bool enabled) { collect_histograms_ = enabled; }
    const std::unordered_map<uint32_t, KernelEventHistograms>&
    kernel_histograms() const
    {
        return kernel_histograms_;
    }
    const ThreadPmuHistograms& pmu_histograms() const
    {
        return pmu_histograms_;
    }

    // Names are indexed by PmuSample::event_index.  Set once before samples
    // arrive.
    void set_pmu_event_names(std::vector<std::string> names);
    void on_pmu_sample(const PmuSample& sample, const CallStack& stack);
    uint64_t pmu_samples() const { return pmu_samples_; }

    // Must be called before CallStack applies the event: the interval that
    // ends at event.ts belongs to the old top frame.
    void on_function_event(const TraceEvent& event, const CallStack& stack);
    void on_kernel_event(const KernelEvent& event, const CallStack& stack);
    void finish(uint64_t stop_ts, const CallStack& stack);

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
        uint64_t span_token = 0;
        uint32_t user_depth = 0;
    };

    struct ReclaimInterval {
        uint64_t begin_ts = 0;
        uint64_t id = 0;
        uint64_t order = 0;
        uint64_t gfp = 0;
        uint64_t span_token = 0;
        uint32_t user_depth = 0;
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
        std::vector<ReclaimInterval> reclaims;
        uint32_t reclaim_depth = 0;
        uint64_t reclaim_begin_ns = 0;
        uint64_t reclaim_id = 0;
        uint64_t offcpu_span_token = 0;
        uint64_t offcpu_span_start_ns = 0;
        uint32_t offcpu_user_depth = 0;
        uint64_t runqueue_span_token = 0;
        uint64_t runqueue_span_start_ns = 0;
        uint32_t runqueue_user_depth = 0;
        bool partial = false;
        uint64_t out_of_order = 0;
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
    void record_kernel_histogram(uint32_t tid, const CallStack& stack,
                                 const std::string& event, uint64_t ns,
                                 bool incomplete = false);
    void record_pmu_histogram(uint32_t tid, const CallStack& stack,
                              const std::string& event, uint64_t period);
    void record_open_intervals(uint32_t tid, uint64_t ts,
                               const CallStack& stack);
    uint64_t function_span_token(const CallStack& stack, uint32_t tid) const;
    uint64_t innermost_span_token(uint32_t tid, const CallStack& stack) const;
    uint64_t open_span(const CallStack& stack, uint32_t tid,
                       uint32_t user_depth, uint8_t category,
                       const std::string& name, uint64_t ts,
                       std::vector<SpanAttribute> attributes);
    void close_span(uint64_t token, uint64_t ts,
                    std::vector<SpanAttribute> attributes, bool incomplete);
    void emit_point(const CallStack& stack, uint32_t tid, uint32_t user_depth,
                    uint8_t category, const std::string& name, uint64_t ts,
                    std::vector<SpanAttribute> attributes,
                    uint64_t parent_override = 0);
    BlockReason classify_block(const ThreadRuntime& thread) const;
    void on_sched_switch(const KernelEvent& event, const CallStack& stack);
    void on_sched_wakeup(const KernelEvent& event, const CallStack& stack);
    void on_futex(const KernelEvent& event, const CallStack& stack);
    void on_io(const KernelEvent& event, const CallStack& stack);
    void on_net(const KernelEvent& event, const CallStack& stack);
    void on_mm(const KernelEvent& event, const CallStack& stack);
    void on_block(const KernelEvent& event);
    void on_tcp_retransmit(const KernelEvent& event);
    void emit_event(const KernelEvent& event, int depth,
                    const std::string& name, const std::string& attrs);
    uint64_t next_id();
    std::string state_name(uint32_t state) const;

    Output& output_;
    int max_depth_;
    bool verbose_;
    bool collect_histograms_ = false;
    KernelSpanSink* span_sink_ = nullptr;
    uint64_t next_id_ = 1;
    uint64_t kernel_events_ = 0;
    uint64_t out_of_order_ = 0;
    std::unordered_set<uint32_t> targets_;
    std::unordered_set<uint32_t> exited_;
    std::unordered_map<uint32_t, ThreadRuntime> threads_;
    std::unordered_map<BlockKey, BlockPending, BlockKeyHash> block_pending_;
    std::unordered_map<uint32_t, KernelEventHistograms> kernel_histograms_;
    std::vector<std::string> pmu_event_names_;
    ThreadPmuHistograms pmu_histograms_;
    uint64_t pmu_samples_ = 0;
};

}  // namespace callgraph
