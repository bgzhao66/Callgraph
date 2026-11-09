#pragma once

#include <sys/types.h>

#include <string>

namespace callgraph {

class ProcessController {
public:
    // Starts argv under ptrace and returns after the child has exec'd but
    // before the dynamic loader runs.  The child remains stopped until
    // detach() is called.
    static pid_t launch(char* const argv[]);

    static void detach(pid_t pid);

    static std::string exe_path(pid_t pid);

    static bool alive(pid_t pid);
};

}  // namespace callgraph
