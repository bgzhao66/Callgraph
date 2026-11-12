#pragma once

#include <cstdint>
#include <map>
#include <string>
#include <unordered_map>
#include <vector>

#include "callgraph/span.h"

namespace callgraph {

// Converts call events into folded stacks suitable for flamegraph.pl and
// inferno-flamegraph.  Each completed function exit records the current
// root-to-function stack; identical stacks are aggregated.
class FlameGraphSink : public SpanSink {
public:
    explicit FlameGraphSink(const std::vector<FunctionMetadata>& functions);

    uint64_t on_function_enter(uint32_t tid, uint64_t function_id,
                               uint32_t depth, uint64_t ts,
                               const std::string& arguments,
                               uint64_t parent_token) override;

    void on_function_exit(uint32_t tid, uint64_t token, uint64_t function_id,
                          uint64_t ts, SpanCloseReason reason) override;

    std::string render() const;
    size_t unique_stacks() const { return counts_.size(); }
    uint64_t recorded() const { return recorded_; }

private:
    std::string function_name(uint64_t function_id) const;
    static std::string sanitize(std::string name);

    const std::vector<FunctionMetadata>& functions_;

    struct ThreadState {
        std::vector<std::string> stack;
    };
    std::unordered_map<uint32_t, ThreadState> threads_;
    std::map<std::string, uint64_t> counts_;
    uint64_t recorded_ = 0;
};

}  // namespace callgraph
