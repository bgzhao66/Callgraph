#pragma once

#include <sys/types.h>

#include <cstdint>
#include <string>
#include <vector>

namespace callgraph {

struct LoadedModule {
    std::string path;
    uint64_t start = 0;
    uint64_t end = 0;
};

// Discovers the ELF files mapped by a process by reading /proc/<pid>/maps.
class ModuleManager {
public:
    explicit ModuleManager(pid_t pid) : pid_(pid) {}

    std::vector<LoadedModule> scan() const;

private:
    pid_t pid_;
};

}  // namespace callgraph
