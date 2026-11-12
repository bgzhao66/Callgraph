#include "callgraph/flame_graph.h"

#include <algorithm>
#include <utility>

namespace callgraph {

FlameGraphSink::FlameGraphSink(
    const std::vector<FunctionMetadata>& functions)
    : functions_(functions)
{
}

std::string FlameGraphSink::function_name(uint64_t function_id) const
{
    if (function_id < functions_.size() && !functions_[function_id].name.empty())
        return functions_[function_id].name;
    return "unknown(" + std::to_string(function_id) + ")";
}

std::string FlameGraphSink::sanitize(std::string name)
{
    for (char& c : name) {
        if (c == ';')
            c = ':';
        else if (c == '\n' || c == '\r' || c == '\t')
            c = ' ';
    }
    return name;
}

uint64_t FlameGraphSink::on_function_enter(uint32_t tid,
                                           uint64_t function_id,
                                           uint32_t depth, uint64_t ts,
                                           const std::string& arguments,
                                           uint64_t parent_token)
{
    (void)depth;
    (void)ts;
    (void)arguments;
    (void)parent_token;
    threads_[tid].stack.push_back(
        sanitize(function_name(function_id)));
    return 0;
}

void FlameGraphSink::on_function_exit(uint32_t tid, uint64_t token,
                                      uint64_t function_id, uint64_t ts,
                                      SpanCloseReason reason)
{
    (void)token;
    (void)function_id;
    (void)ts;

    auto thread = threads_.find(tid);
    if (thread == threads_.end() || thread->second.stack.empty())
        return;

    std::string folded;
    size_t total = 0;
    for (const auto& name : thread->second.stack)
        total += name.size() + 1;
    folded.reserve(total + 16);

    for (size_t i = 0; i < thread->second.stack.size(); ++i) {
        if (i != 0)
            folded.push_back(';');
        folded += thread->second.stack[i];
    }
    if (reason != SpanCloseReason::Return)
        folded += ";[incomplete]";

    ++counts_[std::move(folded)];
    ++recorded_;

    thread->second.stack.pop_back();
    if (thread->second.stack.empty())
        threads_.erase(thread);
}

std::string FlameGraphSink::render() const
{
    std::string out;
    for (const auto& [stack, count] : counts_) {
        out += stack;
        out.push_back(' ');
        out += std::to_string(count);
        out.push_back('\n');
    }
    return out;
}

}  // namespace callgraph
