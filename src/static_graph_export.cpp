#include "callgraph/static_graph_export.h"

#include <cstddef>
#include <ostream>
#include <sstream>
#include <string>
#include <vector>

namespace callgraph {
namespace {

std::string display_name(const FunctionInfo& function)
{
    return function.name.empty() ? function.linkage_name : function.name;
}

struct Frame {
    size_t function = 0;
    size_t next_child = 0;
    bool last = true;
};

void write_connector(std::ostream& out, const std::vector<Frame>& stack,
                     bool last)
{
    // The root has no prefix; every deeper ancestor contributes a column.
    for (size_t i = 1; i < stack.size(); ++i)
        out << (stack[i].last ? "    " : "│   ");
    out << (last ? "└── " : "├── ");
}

}  // namespace

void write_static_graph(const StaticGraphView& view, std::ostream& out)
{
    if (!view.graph || !view.functions)
        return;

    const StaticCallGraph& graph = *view.graph;
    const std::vector<FunctionInfo>& functions = *view.functions;

    for (const size_t root : graph.roots) {
        if (root >= functions.size())
            continue;

        out << display_name(functions[root]) << '\n';
        if (root >= graph.edges.size())
            continue;

        std::vector<unsigned char> on_path(functions.size(), 0);
        std::vector<Frame> stack;
        stack.push_back({root, 0, true});
        on_path[root] = 1;

        while (!stack.empty()) {
            Frame& frame = stack.back();
            const std::vector<size_t>& callees = graph.edges[frame.function];
            if (frame.next_child >= callees.size()) {
                on_path[frame.function] = 0;
                stack.pop_back();
                continue;
            }

            const size_t child = callees[frame.next_child++];
            if (child >= functions.size() || child >= graph.edges.size())
                continue;

            const bool last = frame.next_child >= callees.size();
            write_connector(out, stack, last);
            out << display_name(functions[child]);
            if (on_path[child]) {
                out << " [recursive]\n";
                continue;
            }

            out << '\n';
            on_path[child] = 1;
            stack.push_back({child, 0, last});
        }
    }
}

std::string render_static_graph(const StaticGraphView& view)
{
    std::ostringstream out;
    write_static_graph(view, out);
    return out.str();
}

}  // namespace callgraph
