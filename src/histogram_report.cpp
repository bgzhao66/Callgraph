#include "callgraph/histogram_report.h"

#include <algorithm>
#include <cstdio>
#include <functional>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

namespace callgraph {
namespace {

constexpr size_t kBarWidth = 40;

// Four display columns each, like `tree`.
constexpr const char* kBranch = "├── ";
constexpr const char* kLast = "└── ";
constexpr const char* kVertical = "│   ";
constexpr const char* kBlank = "    ";

struct UnitScale {
    const char* suffix;
    double divisor;
    bool integral;
};

UnitScale choose_unit(uint64_t max_ns)
{
    if (max_ns >= 1000000000ULL)
        return {"s", 1e9, false};
    if (max_ns >= 1000000ULL)
        return {"ms", 1e6, false};
    if (max_ns >= 1000ULL)
        return {"us", 1e3, false};
    return {"ns", 1.0, true};
}

// Bucket k >= 1 covers [2^(k-1), 2^k) ns.  Bucket 0 is exactly 0 ns; display
// it as [0, 1) so the ranges stay contiguous and readable.
uint64_t bucket_lower(int bucket)
{
    if (bucket <= 0)
        return 0;
    if (bucket >= 64)
        return 1ULL << 63;
    return 1ULL << (bucket - 1);
}

uint64_t bucket_upper(int bucket)
{
    if (bucket <= 0)
        return 1;
    if (bucket >= 64)
        return UINT64_MAX;
    return 1ULL << bucket;
}

std::string format_value(uint64_t ns, const UnitScale& unit)
{
    if (unit.integral)
        return std::to_string(ns) + unit.suffix;

    char buffer[64];
    snprintf(buffer, sizeof(buffer), "%.2f%s",
             static_cast<double>(ns) / unit.divisor, unit.suffix);
    return buffer;
}

std::string right_justify(const std::string& text, size_t width)
{
    if (text.size() >= width)
        return text;
    return std::string(width - text.size(), ' ') + text;
}

struct TreeLine {
    std::string text;
    uint64_t total_ns = 0;
    bool has_total = false;
};

void append_tree_node(std::vector<TreeLine>& lines, const std::string& prefix,
                      const std::string& name, const std::string& note,
                      uint64_t total_ns, bool has_total)
{
    TreeLine line;
    line.text = prefix + name + note;
    line.total_ns = total_ns;
    line.has_total = has_total;
    lines.push_back(std::move(line));
}

// Terminal columns, not bytes: the tree connectors are multi-byte UTF-8 but
// each renders as one column.  Counting code points is enough here.
size_t display_width(const std::string& text)
{
    size_t width = 0;
    for (const unsigned char ch : text) {
        if ((ch & 0xC0) != 0x80)
            ++width;
    }
    return width;
}

// Tree lines are flushed after the whole tree is known so the totals line up
// in one column.  A single unit is chosen for the tree so the column stays
// comparable even when individual nodes span different unit ranges.
void append_tree_lines(std::string& out, const std::vector<TreeLine>& lines)
{
    uint64_t max_total = 0;
    size_t text_width = 0;
    for (const TreeLine& line : lines) {
        text_width = std::max(text_width, display_width(line.text));
        if (line.has_total)
            max_total = std::max(max_total, line.total_ns);
    }

    const UnitScale unit = choose_unit(max_total);

    size_t value_width = 0;
    for (const TreeLine& line : lines) {
        if (line.has_total)
            value_width = std::max(
                value_width, format_value(line.total_ns, unit).size());
    }

    for (const TreeLine& line : lines) {
        out += line.text;
        if (line.has_total) {
            out.append(text_width - display_width(line.text), ' ');
            out += "  ";
            out += right_justify(format_value(line.total_ns, unit),
                                 value_width);
        }
        out += '\n';
    }
}

void merge_histogram(LatencyHistogram& target, const LatencyHistogram& source)
{
    if (source.calls == 0)
        return;

    if (target.calls == 0) {
        target = source;
        return;
    }

    target.calls += source.calls;
    target.total_ns += source.total_ns;
    target.min_ns = std::min(target.min_ns, source.min_ns);
    target.max_ns = std::max(target.max_ns, source.max_ns);
    for (int i = 0; i < kLatencyBuckets; ++i)
        target.buckets[i] += source.buckets[i];
}

// One bar per histogram entry.  Its length is the function's inclusive time
// relative to the root span's duration, so it shows how much of the tree's
// elapsed time this node accounts for.  Bucket counts share the bar: latency
// distribution and overall share are separate dimensions.
void append_histogram_body(std::string& out, const LatencyHistogram& hist,
                           const std::string& indent, uint64_t root_total_ns)
{
    if (hist.calls == 0)
        return;

    int first = -1;
    int last = -1;
    for (int i = 0; i < kLatencyBuckets; ++i) {
        if (hist.buckets[i] == 0)
            continue;
        if (first < 0)
            first = i;
        last = i;
    }
    if (first < 0)
        return;

    const UnitScale unit = choose_unit(hist.max_ns);

    size_t bar = 0;
    if (root_total_ns != 0 && hist.total_ns != 0) {
        bar = static_cast<size_t>(
            static_cast<double>(hist.total_ns) /
            static_cast<double>(root_total_ns) *
            static_cast<double>(kBarWidth));
        if (bar == 0)
            bar = 1;
        if (bar > kBarWidth)
            bar = kBarWidth;
    }
    if (bar != 0) {
        out += indent;
        out.append(bar, '-');
        out += '\n';
    }

    char header[512];
    snprintf(header, sizeof(header),
             "calls=%llu  total=%s  avg=%s  min=%s  max=%s",
             static_cast<unsigned long long>(hist.calls),
             format_value(hist.total_ns, unit).c_str(),
             format_value(hist.total_ns / hist.calls, unit).c_str(),
             format_value(hist.min_ns, unit).c_str(),
             format_value(hist.max_ns, unit).c_str());
    out += indent;
    out += header;
    out += '\n';

    size_t value_width = 0;
    for (int i = first; i <= last; ++i) {
        value_width =
            std::max(value_width, format_value(bucket_lower(i), unit).size());
        value_width =
            std::max(value_width, format_value(bucket_upper(i), unit).size());
    }

    std::vector<std::string> labels;
    size_t label_width = 0;
    for (int i = first; i <= last; ++i) {
        std::string label =
            "[ " + right_justify(format_value(bucket_lower(i), unit),
                                 value_width) +
            ", " +
            right_justify(format_value(bucket_upper(i), unit), value_width) +
            ")";
        label_width = std::max(label_width, label.size());
        labels.push_back(std::move(label));
    }

    size_t count_width = 1;
    for (int i = first; i <= last; ++i) {
        count_width =
            std::max(count_width, std::to_string(hist.buckets[i]).size());
    }

    for (int i = first; i <= last; ++i) {
        const uint64_t count = hist.buckets[i];

        const std::string& label = labels[static_cast<size_t>(i - first)];
        out += indent;
        out += label;
        out += std::string(label_width - label.size(), ' ');
        out += "  ";
        out += right_justify(std::to_string(count), count_width);
        out += '\n';
    }
}

struct HistogramKey {
    uint32_t depth = 0;
    uint64_t function_id = 0;

    bool operator==(const HistogramKey& other) const = default;
};

struct HistogramKeyHash {
    size_t operator()(const HistogramKey& key) const noexcept
    {
        uint64_t value = key.function_id * 0x9e3779b97f4a7c15ULL;
        value ^= static_cast<uint64_t>(key.depth) + 0x9e3779b97f4a7c15ULL +
                 (value << 6) + (value >> 2);
        return static_cast<size_t>(value);
    }
};

struct HistogramEntry {
    uint32_t depth = 0;
    uint64_t function_id = 0;
    std::string name;
    LatencyHistogram histogram;
    bool has_histogram = false;
    bool recursive = false;
    bool incomplete = false;
};

}  // namespace

std::string format_histogram_report(const LatencyStats& stats,
                                    const std::vector<std::string>& names)
{
    const auto& threads = stats.threads();
    if (threads.empty())
        return "=== no calls observed ===\n";

    std::vector<uint32_t> tids;
    tids.reserve(threads.size());
    for (const auto& [tid, thread] : threads) {
        (void)thread;
        tids.push_back(tid);
    }
    std::sort(tids.begin(), tids.end());

    std::string out;
    bool first_thread = true;

    for (uint32_t tid : tids) {
        if (!first_thread)
            out += '\n';
        first_thread = false;

        out += "=== thread " + std::to_string(tid) + " ===\n";

        const ThreadLatency& thread = threads.at(tid);

        // Completed edges: parent -> children.
        std::unordered_map<uint64_t, std::vector<uint64_t>> children;
        for (const auto& [edge, hist] : thread.edges) {
            (void)hist;
            children[edge.parent].push_back(edge.child);
        }

        auto edge_sequence = [&](uint64_t parent,
                                 uint64_t child) -> uint64_t {
            const auto it = thread.edge_sequence.find({parent, child});
            return it == thread.edge_sequence.end() ? UINT64_MAX : it->second;
        };
        auto name_of = [&](uint64_t id) -> std::string {
            return id < names.size() ? names[id] : std::string("<unknown>");
        };
        auto sort_children = [&](uint64_t parent,
                                 std::vector<uint64_t>& kids) {
            std::sort(kids.begin(), kids.end(), [&](uint64_t a, uint64_t b) {
                const uint64_t seq_a = edge_sequence(parent, a);
                const uint64_t seq_b = edge_sequence(parent, b);
                if (seq_a != seq_b)
                    return seq_a < seq_b;

                const std::string name_a = name_of(a);
                const std::string name_b = name_of(b);
                if (name_a != name_b)
                    return name_a < name_b;
                return a < b;
            });
        };

        for (auto& [parent, kids] : children)
            sort_children(parent, kids);

        // Entries are inserted on first DFS visit so the histogram section
        // follows the same top-to-bottom order as the Tree section.  They are
        // reset for every root so that each root's tree and histograms stay
        // paired instead of all trees being emitted before all histograms.
        std::vector<HistogramEntry> entries;
        std::unordered_map<HistogramKey, size_t, HistogramKeyHash> entry_index;
        // Tree lines are buffered per root so node totals can be aligned.
        std::vector<TreeLine> tree_lines;
        auto record = [&](uint32_t depth, uint64_t function_id,
                          const LatencyHistogram* hist, bool recursive,
                          bool incomplete) {
            const HistogramKey key{depth, function_id};
            auto found = entry_index.find(key);
            if (found == entry_index.end()) {
                found = entry_index.emplace(key, entries.size()).first;
                HistogramEntry entry;
                entry.depth = depth;
                entry.function_id = function_id;
                entry.name = name_of(function_id);
                entries.push_back(std::move(entry));
            }

            auto& entry = entries[found->second];
            entry.recursive = entry.recursive || recursive;
            entry.incomplete = entry.incomplete || incomplete;
            if (hist) {
                merge_histogram(entry.histogram, *hist);
                entry.has_histogram = hist->calls != 0;
            }
        };

        auto render_histograms = [&]() {
            out += "\nHistograms:\n";

            // The bar denominator is the root span's duration.  The root entry
            // is recorded first, so entries.front() is the depth-0 span.  When
            // the root is still live at shutdown its duration is unknown;
            // omit bars rather than scale children against an arbitrary entry.
            uint64_t root_total_ns = 0;
            if (!entries.empty() && entries.front().has_histogram)
                root_total_ns = entries.front().histogram.total_ns;

            for (const HistogramEntry& entry : entries) {
                out += std::to_string(entry.depth);
                out += ". ";
                out += entry.name;
                if (entry.recursive)
                    out += "  [recursive]";
                if (entry.incomplete)
                    out += "  [incomplete]";
                out += '\n';

                if (entry.has_histogram)
                    append_histogram_body(out, entry.histogram, "   ",
                                          root_total_ns);
                else
                    out += "   calls=0  [incomplete]\n";
            }
        };

        std::unordered_set<uint64_t> path;

        // Completed subtree.  A cycle cut-off keeps recursion bounded.
        std::function<void(uint64_t, uint64_t, uint32_t,
                           const std::string&, bool)>
            render_completed = [&](uint64_t parent, uint64_t child,
                                   uint32_t depth,
                                   const std::string& parent_prefix,
                                   bool is_last) {
                const auto it = thread.edges.find({parent, child});
                if (it == thread.edges.end())
                    return;

                const std::string line_prefix =
                    parent_prefix + (is_last ? kLast : kBranch);
                const std::string detail_prefix =
                    parent_prefix + (is_last ? kBlank : kVertical);

                const bool recursive = path.contains(child);
                record(depth, child, &it->second, recursive, false);
                append_tree_node(tree_lines, line_prefix, name_of(child),
                                 recursive ? "  [recursive]" : "",
                                 it->second.total_ns, true);
                if (recursive)
                    return;

                const bool inserted = path.insert(child).second;
                const auto kids = children.find(child);
                if (kids != children.end()) {
                    for (size_t i = 0; i < kids->second.size(); ++i) {
                        render_completed(child, kids->second[i], depth + 1,
                                         detail_prefix,
                                         i + 1 == kids->second.size());
                    }
                }
                if (inserted)
                    path.erase(child);
            };

        // Live chain at shutdown.  Its frames have no duration, but their
        // completed children still belong underneath them.
        std::function<void(size_t, const std::string&, bool)> render_live =
            [&](size_t index, const std::string& parent_prefix, bool is_last) {
                std::string line_prefix;
                std::string detail_prefix;
                if (index != 0) {
                    line_prefix =
                        parent_prefix + (is_last ? kLast : kBranch);
                    detail_prefix =
                        parent_prefix + (is_last ? kBlank : kVertical);
                }

                const uint64_t node = thread.live_stack[index];
                const uint64_t parent =
                    index == 0 ? kRootFunction
                               : thread.live_stack[index - 1];

                const auto edge = thread.edges.find({parent, node});
                if (edge != thread.edges.end()) {
                    record(static_cast<uint32_t>(index), node, &edge->second,
                           false, true);
                    append_tree_node(tree_lines, line_prefix, name_of(node),
                                     "  [incomplete]", edge->second.total_ns,
                                     true);
                } else {
                    record(static_cast<uint32_t>(index), node, nullptr, false,
                           true);
                    append_tree_node(tree_lines, line_prefix, name_of(node),
                                     "  [incomplete]", 0, false);
                }

                const bool inserted = path.insert(node).second;

                std::vector<uint64_t> kids;
                const auto it = children.find(node);
                if (it != children.end()) {
                    for (uint64_t grandchild : it->second) {
                        // The next live frame is rendered by the chain itself.
                        if (index + 1 < thread.live_stack.size() &&
                            grandchild == thread.live_stack[index + 1])
                            continue;
                        kids.push_back(grandchild);
                    }
                }

                const bool has_live_child =
                    index + 1 < thread.live_stack.size();
                const size_t total =
                    kids.size() + (has_live_child ? 1 : 0);

                for (size_t i = 0; i < kids.size(); ++i) {
                    render_completed(node, kids[i],
                                     static_cast<uint32_t>(index + 1),
                                     detail_prefix, i + 1 == total);
                }
                if (has_live_child)
                    render_live(index + 1, detail_prefix, true);

                if (inserted)
                    path.erase(node);
            };

        std::vector<uint64_t> roots;
        const auto root_children = children.find(kRootFunction);
        if (root_children != children.end())
            roots = root_children->second;
        if (!thread.live_stack.empty() &&
            std::find(roots.begin(), roots.end(), thread.live_stack[0]) ==
                roots.end()) {
            roots.push_back(thread.live_stack[0]);
        }
        sort_children(kRootFunction, roots);

        bool first_root = true;
        for (uint64_t root : roots) {
            const bool live = !thread.live_stack.empty() &&
                              root == thread.live_stack[0];
            const auto it = thread.edges.find({kRootFunction, root});
            if (!live && it == thread.edges.end())
                continue;

            if (!first_root)
                out += '\n';
            first_root = false;

            entries.clear();
            entry_index.clear();
            tree_lines.clear();
            path.clear();

            out += "Tree:\n";

            if (live) {
                render_live(0, "", false);
            } else {
                record(0, root, &it->second, false, false);
                append_tree_node(tree_lines, "", name_of(root), "",
                                 it->second.total_ns, true);
                const bool inserted = path.insert(root).second;
                const auto kids = children.find(root);
                if (kids != children.end()) {
                    for (size_t i = 0; i < kids->second.size(); ++i) {
                        render_completed(root, kids->second[i], 1, "",
                                         i + 1 == kids->second.size());
                    }
                }
                if (inserted)
                    path.erase(root);
            }

            append_tree_lines(out, tree_lines);
            render_histograms();
        }

        if (thread.incomplete != 0) {
            out += "incomplete: " + std::to_string(thread.incomplete) +
                   " call(s)\n";
        }
    }

    return out;
}

}  // namespace callgraph
