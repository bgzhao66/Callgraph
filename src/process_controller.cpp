#include "callgraph/process_controller.h"

#include <signal.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <cstdint>

#include "callgraph/common.h"

namespace callgraph {
namespace {

[[noreturn]] void launch_failure(pid_t pid, const char* what)
{
    const int saved = errno;
    if (pid > 0) {
        kill(pid, SIGKILL);
        waitpid(pid, nullptr, 0);
    }
    fail("%s: %s", what, errno_string(saved).c_str());
}

}  // namespace

pid_t ProcessController::launch(char* const argv[])
{
    const pid_t pid = fork();
    if (pid < 0)
        fail("fork: %s", errno_string(errno).c_str());

    if (pid == 0) {
        if (ptrace(PTRACE_TRACEME, 0, nullptr, nullptr) < 0)
            _exit(127);
        raise(SIGSTOP);
        execvp(argv[0], argv);
        _exit(127);
    }

    int status = 0;
    if (waitpid(pid, &status, 0) < 0)
        launch_failure(pid, "waitpid for child stop");
    if (!WIFSTOPPED(status))
        launch_failure(pid, "child exited before stopping");

    if (ptrace(PTRACE_SETOPTIONS, pid, nullptr,
               reinterpret_cast<void*>(static_cast<uintptr_t>(PTRACE_O_TRACEEXEC))) < 0)
        launch_failure(pid, "ptrace(PTRACE_SETOPTIONS)");

    if (ptrace(PTRACE_CONT, pid, nullptr, nullptr) < 0)
        launch_failure(pid, "ptrace(PTRACE_CONT)");

    if (waitpid(pid, &status, 0) < 0)
        launch_failure(pid, "waitpid for exec event");

    const int expected = SIGTRAP | (PTRACE_EVENT_EXEC << 8);
    if (!WIFSTOPPED(status) || (status >> 8) != expected)
        launch_failure(pid, "child failed to exec");

    return pid;
}

void ProcessController::detach(pid_t pid)
{
    if (ptrace(PTRACE_DETACH, pid, nullptr, nullptr) < 0)
        fail("ptrace(PTRACE_DETACH) on %d: %s", pid,
             errno_string(errno).c_str());
}

std::string ProcessController::exe_path(pid_t pid)
{
    char proc_path[64];
    snprintf(proc_path, sizeof(proc_path), "/proc/%d/exe", pid);

    std::string path = read_symlink(proc_path);
    static const std::string deleted_suffix = " (deleted)";
    if (path.size() > deleted_suffix.size() &&
        path.compare(path.size() - deleted_suffix.size(), deleted_suffix.size(),
                     deleted_suffix) == 0) {
        path.resize(path.size() - deleted_suffix.size());
        log_warn("executable of pid %d has been deleted: %s", pid, path.c_str());
    }
    return path;
}

bool ProcessController::alive(pid_t pid)
{
    if (pid <= 0)
        return false;
    return kill(pid, 0) == 0 || errno == EPERM;
}

}  // namespace callgraph
