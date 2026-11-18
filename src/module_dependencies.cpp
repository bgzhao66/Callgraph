#include "callgraph/module_dependencies.h"

#include <elf.h>
#include <fcntl.h>
#include <gelf.h>
#include <libelf.h>
#include <sys/wait.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <string>
#include <vector>

#include "callgraph/common.h"

namespace callgraph {
namespace {

struct ElfFile {
    int fd = -1;
    Elf* elf = nullptr;

    ~ElfFile()
    {
        if (elf)
            elf_end(elf);
        if (fd >= 0)
            close(fd);
    }
};

bool read_elf_facts(const std::string& path, std::string* interpreter,
                    bool* has_needed, std::string* reason)
{
    ElfFile file;
    file.fd = open(path.c_str(), O_RDONLY | O_CLOEXEC);
    if (file.fd < 0) {
        *reason = "cannot open module: " + errno_string(errno);
        return false;
    }
    file.elf = elf_begin(file.fd, ELF_C_READ, nullptr);
    if (!file.elf) {
        *reason = std::string("cannot read ELF: ") + elf_errmsg(-1);
        return false;
    }

    size_t phnum = 0;
    if (elf_getphdrnum(file.elf, &phnum) != 0) {
        *reason = std::string("cannot read program headers: ") + elf_errmsg(-1);
        return false;
    }
    for (size_t i = 0; i < phnum; ++i) {
        GElf_Phdr phdr;
        if (!gelf_getphdr(file.elf, i, &phdr))
            continue;
        if (phdr.p_type != PT_INTERP || phdr.p_filesz == 0)
            continue;
        std::vector<char> buffer(static_cast<size_t>(phdr.p_filesz) + 1, '\0');
        const ssize_t got = pread(file.fd, buffer.data(), phdr.p_filesz,
                                  static_cast<off_t>(phdr.p_offset));
        if (got <= 0)
            continue;
        interpreter->assign(buffer.data());
        break;
    }

    Elf_Scn* scn = nullptr;
    while ((scn = elf_nextscn(file.elf, scn)) != nullptr) {
        GElf_Shdr shdr;
        if (!gelf_getshdr(scn, &shdr) || shdr.sh_type != SHT_DYNAMIC)
            continue;
        Elf_Data* data = elf_getdata(scn, nullptr);
        if (!data)
            continue;
        const size_t count =
            shdr.sh_entsize == 0 ? 0 : shdr.sh_size / shdr.sh_entsize;
        for (size_t i = 0; i < count; ++i) {
            GElf_Dyn dyn;
            if (!gelf_getdyn(data, static_cast<int>(i), &dyn))
                continue;
            if (dyn.d_tag == DT_NEEDED) {
                *has_needed = true;
                break;
            }
        }
        if (*has_needed)
            break;
    }
    return true;
}

std::string trim(const std::string& text)
{
    const size_t begin = text.find_first_not_of(" \t\r\n");
    if (begin == std::string::npos)
        return {};
    const size_t end = text.find_last_not_of(" \t\r\n");
    return text.substr(begin, end - begin + 1);
}

bool run_loader_list(const std::string& loader, const std::string& module,
                     std::vector<std::string>* dependencies,
                     std::string* reason)
{
    int pipe_fds[2] = {-1, -1};
    if (pipe2(pipe_fds, O_CLOEXEC) != 0) {
        *reason = "cannot create pipe: " + errno_string(errno);
        return false;
    }

    const pid_t pid = fork();
    if (pid < 0) {
        close(pipe_fds[0]);
        close(pipe_fds[1]);
        *reason = "cannot fork: " + errno_string(errno);
        return false;
    }
    if (pid == 0) {
        dup2(pipe_fds[1], STDOUT_FILENO);
        const int null_fd = open("/dev/null", O_WRONLY | O_CLOEXEC);
        if (null_fd >= 0)
            dup2(null_fd, STDERR_FILENO);
        close(pipe_fds[0]);
        close(pipe_fds[1]);
        execl(loader.c_str(), loader.c_str(), "--list", module.c_str(),
              static_cast<char*>(nullptr));
        _exit(127);
    }

    close(pipe_fds[1]);
    std::string output;
    char buffer[4096];
    for (;;) {
        const ssize_t got = read(pipe_fds[0], buffer, sizeof(buffer));
        if (got > 0) {
            output.append(buffer, static_cast<size_t>(got));
            continue;
        }
        if (got < 0 && errno == EINTR)
            continue;
        break;
    }
    close(pipe_fds[0]);

    int status = 0;
    while (waitpid(pid, &status, 0) < 0) {
        if (errno != EINTR) {
            *reason = "cannot wait for the dynamic loader: " +
                      errno_string(errno);
            return false;
        }
    }
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        *reason = "dynamic loader could not list dependencies of " + module;
        return false;
    }

    size_t start = 0;
    while (start <= output.size()) {
        const size_t end = output.find('\n', start);
        const std::string line =
            output.substr(start, end == std::string::npos ? end : end - start);
        start = end == std::string::npos ? output.size() + 1 : end + 1;

        const size_t arrow = line.find("=> ");
        if (arrow == std::string::npos)
            continue;
        const size_t value_start = arrow + 3;
        const size_t address = line.find(" (0x", value_start);
        std::string dependency =
            trim(line.substr(value_start, address == std::string::npos
                                               ? address
                                               : address - value_start));
        if (dependency.empty() || dependency == "not found")
            continue;
        if (dependency.find("linux-vdso") != std::string::npos)
            continue;
        dependencies->push_back(std::move(dependency));
    }
    return true;
}

std::string host_interpreter()
{
    std::string interpreter;
    bool has_needed = false;
    std::string reason;
    if (!read_elf_facts("/proc/self/exe", &interpreter, &has_needed, &reason))
        return {};
    return interpreter;
}

}  // namespace

bool module_dependencies(const std::string& path,
                         std::vector<std::string>* modules,
                         std::string* reason)
{
    modules->clear();
    if (elf_version(EV_CURRENT) == EV_NONE) {
        *reason = "libelf initialization failed";
        return false;
    }

    std::string interpreter;
    bool has_needed = false;
    if (!read_elf_facts(path, &interpreter, &has_needed, reason))
        return false;

    modules->push_back(path);
    if (interpreter.empty() && !has_needed)
        return true;  // static executable: no dependencies

    if (interpreter.empty())
        interpreter = host_interpreter();
    if (interpreter.empty()) {
        *reason = "no dynamic loader is available to resolve dependencies";
        return false;
    }

    std::vector<std::string> dependencies;
    if (!run_loader_list(interpreter, path, &dependencies, reason))
        return false;

    for (const auto& dependency : dependencies) {
        if (dependency == path)
            continue;
        if (access(dependency.c_str(), R_OK) != 0) {
            log_verbose("skipping unresolved dependency %s",
                        dependency.c_str());
            continue;
        }
        if (std::find(modules->begin(), modules->end(), dependency) ==
            modules->end())
            modules->push_back(dependency);
    }
    return true;
}

}  // namespace callgraph
