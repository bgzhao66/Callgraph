#include "callgraph/static_graph_export.h"

#include <cstddef>
#include <ostream>
#include <sstream>
#include <string>
#include <vector>

namespace callgraph {
namespace {

std::string display_name(const StaticGraphFunction& function)
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

bool has_in_module_children(const StaticGraphModule& module, size_t index)
{
    if (index >= module.edges.size())
        return false;
    for (const size_t child : module.edges[index]) {
        if (child < module.functions.size())
            return true;
    }
    return false;
}

}  // namespace

void write_static_graph(const StaticGraphModule& module, std::ostream& out)
{
    const std::vector<StaticGraphFunction>& functions = module.functions;
    if (functions.empty())
        return;

    // A function with no in-module callees has no branch to suppress, so
    // repeated leaves still print plainly.
    std::vector<unsigned char> has_children(functions.size(), 0);
    for (size_t i = 0; i < functions.size(); ++i)
        has_children[i] = has_in_module_children(module, i);

    std::vector<unsigned char> expanded(functions.size(), 0);
    std::vector<unsigned char> on_path(functions.size(), 0);
    std::vector<Frame> stack;
    bool wrote_section = false;

    for (const size_t root : module.roots) {
        if (root >= functions.size())
            continue;

        // One blank line between root sections, never before the first.
        if (wrote_section)
            out << '\n';
        wrote_section = true;

        out << display_name(functions[root]);
        if (root >= module.edges.size()) {
            out << '\n';
            continue;
        }

        if (expanded[root]) {
            if (has_children[root])
                out << " [...]";
            out << '\n';
            continue;
        }
        expanded[root] = 1;

        out << '\n';
        if (!has_children[root])
            continue;

        stack.clear();
        on_path[root] = 1;
        stack.push_back({root, 0, true});

        while (!stack.empty()) {
            Frame& frame = stack.back();
            const std::vector<size_t>& callees = module.edges[frame.function];
            if (frame.next_child >= callees.size()) {
                on_path[frame.function] = 0;
                stack.pop_back();
                continue;
            }

            const size_t child = callees[frame.next_child++];
            if (child >= functions.size() || child >= module.edges.size())
                continue;

            const bool last = frame.next_child >= callees.size();
            write_connector(out, stack, last);
            out << display_name(functions[child]);
            if (on_path[child]) {
                // A cycle takes precedence over the already-expanded marker.
                out << " [recursive]\n";
                continue;
            }
            if (expanded[child]) {
                if (has_children[child])
                    out << " [...]";
                out << '\n';
                continue;
            }

            expanded[child] = 1;
            out << '\n';
            if (!has_children[child])
                continue;

            on_path[child] = 1;
            stack.push_back({child, 0, last});
        }
    }
}

std::string render_static_graph(const StaticGraphModule& module)
{
    std::ostringstream out;
    write_static_graph(module, out);
    return out.str();
}

}  // namespace callgraph
