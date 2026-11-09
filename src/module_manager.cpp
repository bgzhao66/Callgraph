#include "callgraph/module_manager.h"

#include <algorithm>
#include <cstdio>
#include <fstream>
#include <sstream>
#include <string>
#include <unordered_set>
#include <vector>

#include "callgraph/common.h"

namespace callgraph {

std::vector<LoadedModule> ModuleManager::scan() const
{
    char maps_path[64];
    snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", pid_);

    std::ifstream maps(maps_path);
    if (!maps)
        fail("cannot read %s: %s", maps_path, errno_string(errno).c_str());

    std::vector<LoadedModule> modules;
    std::unordered_set<std::string> seen;
    std::string line;

    while (std::getline(maps, line)) {
        std::istringstream fields(line);
        std::string range;
        std::string perms;
        std::string offset;
        std::string device;
        std::string inode;
        if (!(fields >> range >> perms >> offset >> device >> inode))
            continue;

        std::string path;
        std::getline(fields, path);
        const auto first = path.find_first_not_of(" \t");
        if (first == std::string::npos)
            continue;
        path.erase(0, first);

        if (path.empty() || path[0] != '/')
            continue;  // [vdso], [vsyscall], anonymous mappings, ...
        if (perms.find('x') == std::string::npos)
            continue;

        static const std::string deleted_suffix = " (deleted)";
        if (path.size() > deleted_suffix.size() &&
            path.compare(path.size() - deleted_suffix.size(),
                         deleted_suffix.size(), deleted_suffix) == 0) {
            log_verbose("skipping deleted mapping: %s", path.c_str());
            continue;
        }

        if (!seen.insert(path).second)
            continue;

        unsigned long long start = 0;
        unsigned long long end = 0;
        if (sscanf(range.c_str(), "%llx-%llx", &start, &end) != 2)
            continue;

        modules.push_back({path, static_cast<uint64_t>(start),
                           static_cast<uint64_t>(end)});
    }

    std::sort(modules.begin(), modules.end(),
              [](const LoadedModule& left, const LoadedModule& right) {
                  return left.path < right.path;
              });
    return modules;
}

}  // namespace callgraph
