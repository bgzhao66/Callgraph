// SPDX-License-Identifier: AGPL-3.0-only
#include "static_internal.h"

#include <algorithm>
#include <deque>
#include <limits>
#include <string>
#include <utility>
#include <vector>

namespace callgraph {
namespace internal {
namespace {

constexpr uint64_t kInf = std::numeric_limits<uint64_t>::max();

CodeFactsCollector g_code_facts_collector = nullptr;

StaticPruneResult compute_pruning(const StaticPruneRequest& request,
                                  bool use_code)
{
    if (request.trace_depth < 0)
        return unavailable("trace-depth is unlimited");

    std::vector<Node> nodes;
    Ranges ranges;
    std::string reason;
    if (!build_nodes(request, &nodes, &ranges, &reason))
        return unavailable(reason);

    // Explicit roots are always knowable without a call graph.
    if (request.has_root_scope) {
        StaticPruneResult result;
        result.available = true;
        for (const size_t root : request.roots) {
            if (nodes[root].candidate)
                result.keep.push_back(root);
        }
        result.roots_kept = result.keep.size();
        result.pruned = request.candidates.size() - result.keep.size();
        if (!use_code || request.trace_depth == 0)
            return result;
    } else if (request.attach_mode) {
        return unavailable("attach mode has dynamic roots");
    }

    if (request.is_go_binary)
        return unavailable("Go binaries use growable stacks");

    const StaticGraphFacts* facts =
        request.facts && request.facts->valid() ? request.facts : nullptr;
    if (facts && facts->edges.size() != nodes.size())
        return unavailable("call-graph facts do not match this module");

    std::vector<size_t> entry;
    std::vector<size_t> init;
    std::vector<size_t> exports;
    std::vector<size_t> address_taken;

    if (facts) {
        entry = facts->entry;
        init = facts->init;
        exports = facts->exports;
        address_taken = facts->address_taken;
    } else {
        ElfFacts elf;
        if (!collect_elf_facts(request.module_path, nodes, ranges, &elf,
                               &reason))
            return unavailable(reason);
        if (elf.ifunc != 0)
            return unavailable("IFUNC targets are resolved at runtime");
        if (elf.context_switch)
            return unavailable("setcontext/swapcontext are not modeled");
        entry = elf.global_roots;
        init = elf.init_roots;
        exports = elf.exports;
        for (size_t i = 0; i < nodes.size(); ++i) {
            if (nodes[i].address_taken)
                address_taken.push_back(i);
        }
    }

    if (!use_code) {
        StaticPruneResult result;
        result.available = true;
        const std::vector<size_t> roots =
            static_graph_roots(*request.functions, entry, init, exports,
                               address_taken);
        for (const size_t root : roots) {
            if (root < nodes.size() && nodes[root].candidate)
                add_unique(&result.keep, root);
        }
        std::sort(result.keep.begin(), result.keep.end());
        result.roots_kept = result.keep.size();
        result.pruned = request.candidates.size() - result.keep.size();
        return result;
    }

    const std::vector<std::vector<size_t>>* edges = nullptr;
    std::vector<std::vector<size_t>> scanned;
    if (facts) {
        if (!facts->prunable) {
            return unavailable(facts->prune_reason.empty()
                                   ? "call-graph facts are not prunable"
                                   : facts->prune_reason);
        }
        edges = &facts->edges;
    } else {
        CodeFactsCollector collector = g_code_facts_collector;
        if (!collector)
            return unavailable(
                "no call-graph facts for this module; produce them with "
                "callgraph-disasm and pass --static-graph FILE");
        scanned.resize(nodes.size());
        if (!collector(request.module_path, *request.functions, &nodes, ranges,
                       &scanned, false, &reason))
            return unavailable(reason);
        edges = &scanned;
    }

    std::vector<size_t> seeds;
    if (request.has_root_scope) {
        seeds = request.roots;
    } else {
        seeds = static_graph_roots(*request.functions, entry, init, exports,
                                   address_taken);
    }

    StaticPruneResult result;
    result.available = true;
    if (seeds.empty()) {
        result.reason = "no roots found";
        result.pruned = request.candidates.size();
        return result;
    }

    std::vector<uint64_t> dist(nodes.size(), kInf);
    std::deque<size_t> queue;
    for (const size_t seed : seeds) {
        if (seed >= nodes.size())
            continue;
        if (dist[seed] != 0) {
            dist[seed] = 0;
            queue.push_back(seed);
        }
    }

    const uint64_t limit = static_cast<uint64_t>(request.trace_depth);
    while (!queue.empty()) {
        const size_t u = queue.front();
        queue.pop_front();
        const uint64_t du = dist[u];
        if (du == kInf)
            continue;
        if (nodes[u].candidate && du >= limit)
            continue;

        const uint64_t cost = nodes[u].candidate ? 1 : 0;
        auto relax = [&](size_t v) {
            if (u == v || v >= nodes.size())
                return;
            const uint64_t nd = du + cost;
            if (nd < dist[v]) {
                dist[v] = nd;
                if (cost == 0)
                    queue.push_front(v);
                else
                    queue.push_back(v);
            }
        };

        for (const size_t v : (*edges)[u])
            relax(v);
    }

    for (size_t i = 0; i < nodes.size(); ++i) {
        if (!nodes[i].candidate)
            continue;
        if (dist[i] <= limit && dist[i] != kInf)
            result.keep.push_back(i);
    }
    std::sort(result.keep.begin(), result.keep.end());
    result.roots_kept = 0;
    for (const size_t root : request.roots) {
        if (root < nodes.size() && nodes[root].root && dist[root] != kInf)
            ++result.roots_kept;
    }
    result.pruned = request.candidates.size() - result.keep.size();
    return result;
}

}  // namespace

void add_unique(std::vector<size_t>* values, size_t value)
{
    if (std::find(values->begin(), values->end(), value) == values->end())
        values->push_back(value);
}

StaticPruneResult unavailable(const std::string& reason)
{
    StaticPruneResult result;
    result.available = false;
    result.reason = reason;
    return result;
}

bool build_nodes(const StaticPruneRequest& request, std::vector<Node>* nodes,
                 Ranges* ranges, std::string* reason)
{
    if (!request.functions) {
        *reason = "no function table";
        return false;
    }
    if (request.functions->size() > kMaxFunctions) {
        *reason = "too many functions to analyze";
        return false;
    }

    nodes->clear();
    nodes->resize(request.functions->size());
    uint64_t total_code = 0;
    for (size_t i = 0; i < request.functions->size(); ++i) {
        const FunctionInfo& function = (*request.functions)[i];
        Node& node = (*nodes)[i];
        node.low = function.low_pc;
        node.high = function.high_pc;
        node.file_offset = function.file_offset;
        node.has_code = node.high > node.low;
        if (node.has_code)
            total_code += node.high - node.low;
    }
    if (total_code > kMaxCodeBytes) {
        *reason = "module code too large to analyze";
        return false;
    }

    for (const size_t index : request.candidates) {
        if (index >= nodes->size()) {
            *reason = "candidate index out of range";
            return false;
        }
        (*nodes)[index].candidate = true;
    }
    for (const size_t index : request.roots) {
        if (index >= nodes->size()) {
            *reason = "root index out of range";
            return false;
        }
        (*nodes)[index].root = true;
    }

    ranges->build(*nodes);
    return true;
}

void set_code_facts_collector(CodeFactsCollector collector)
{
    g_code_facts_collector = collector;
}

}  // namespace internal

using namespace internal;

StaticPruneResult prune_statically(const StaticPruneRequest& request)
{
    if (!request.has_root_scope && request.attach_mode)
        return unavailable("attach mode has dynamic roots");
    return compute_pruning(request, true);
}

StaticPruneResult select_roots(const StaticPruneRequest& request)
{
    if (request.trace_depth != 0)
        return unavailable("root-only selection requires trace-depth 0");
    if (request.has_root_scope)
        return compute_pruning(request, false);
    if (request.attach_mode)
        return unavailable("attach mode has dynamic roots");

    // Prefer the full code scan when available: it finds code-materialised
    // roots such as main.  Fall back to ELF metadata when it is not.
    StaticPruneResult result = compute_pruning(request, true);
    if (!result.available)
        result = compute_pruning(request, false);
    if (result.available && request.functions) {
        for (size_t i = 0; i < request.functions->size(); ++i) {
            if ((*request.functions)[i].name != "main")
                continue;
            if (std::find(request.candidates.begin(),
                          request.candidates.end(), i) !=
                request.candidates.end())
                add_unique(&result.keep, i);
        }
        std::sort(result.keep.begin(), result.keep.end());
        result.pruned = request.candidates.size() - result.keep.size();
    }
    return result;
}

std::vector<size_t> static_graph_roots(
    const std::vector<FunctionInfo>& functions,
    const std::vector<size_t>& entry, const std::vector<size_t>& init,
    const std::vector<size_t>& exports,
    const std::vector<size_t>& address_taken)
{
    std::vector<unsigned char> selected(functions.size(), 0);
    const std::vector<size_t>* lists[] = {&entry, &init, &exports,
                                          &address_taken};
    for (const std::vector<size_t>* list : lists) {
        for (const size_t index : *list) {
            if (index < selected.size())
                selected[index] = 1;
        }
    }

    std::vector<size_t> roots;
    for (size_t i = 0; i < functions.size(); ++i) {
        if (selected[i] || functions[i].name == "main")
            roots.push_back(i);
    }

    // `main` first, then ascending address.  Keeps the output stable across
    // runs.
    std::stable_sort(roots.begin(), roots.end(), [&](size_t a, size_t b) {
        const bool main_a = functions[a].name == "main";
        const bool main_b = functions[b].name == "main";
        if (main_a != main_b)
            return main_a;
        if (functions[a].low_pc != functions[b].low_pc)
            return functions[a].low_pc < functions[b].low_pc;
        return a < b;
    });
    return roots;
}

}  // namespace callgraph
