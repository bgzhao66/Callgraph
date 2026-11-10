#include "callgraph/common.h"

#include <cerrno>
#include <climits>
#include <cstdarg>
#include <cstdlib>
#include <cstring>
#include <unistd.h>

#include <cxxabi.h>

namespace callgraph {

LogLevel g_log_level = LogLevel::Normal;

namespace {

void vlog(const char* prefix, const char* fmt, va_list ap)
{
    fprintf(stderr, "callgraph: %s", prefix);
    vfprintf(stderr, fmt, ap);
    fputc('\n', stderr);
}

}  // namespace

void fail(const char* fmt, ...)
{
    char buf[2048];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    throw Error(buf);
}

void log_warn(const char* fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vlog("warning: ", fmt, ap);
    va_end(ap);
}

void log_info(const char* fmt, ...)
{
    if (g_log_level == LogLevel::Quiet)
        return;
    va_list ap;
    va_start(ap, fmt);
    vlog("", fmt, ap);
    va_end(ap);
}

void log_verbose(const char* fmt, ...)
{
    if (g_log_level != LogLevel::Verbose)
        return;
    va_list ap;
    va_start(ap, fmt);
    vlog("", fmt, ap);
    va_end(ap);
}

std::string errno_string(int err)
{
    if (err < 0)
        err = -err;

    // Kernel-internal errno values (include/linux/errno.h) live above the
    // userspace range.  glibc does not know them, so strerror_r() would only
    // report "Unknown error 524".  Name the ones that can reach us through
    // BPF/uprobe syscalls.
    switch (err) {
    case 512: return "Restart system call (ERESTARTSYS, kernel errno 512)";
    case 513: return "Restart system call (ERESTARTNOINTR, kernel errno 513)";
    case 514: return "Restart system call (ERESTARTNOHAND, kernel errno 514)";
    case 515: return "No ioctl command (ENOIOCTLCMD, kernel errno 515)";
    case 516:
        return "Restart system call (ERESTART_RESTARTBLOCK, kernel errno 516)";
    case 517: return "Probe deferred (EPROBE_DEFER, kernel errno 517)";
    case 518: return "Stale file handle (EOPENSTALE, kernel errno 518)";
    case 519: return "Parameter not supported (ENOPARAM, kernel errno 519)";
    case 521: return "Bad file handle (EBADHANDLE, kernel errno 521)";
    case 522: return "Synchronization mismatch (ENOTSYNC, kernel errno 522)";
    case 523: return "Stale cookie (EBADCOOKIE, kernel errno 523)";
    case 524: return "Operation not supported (ENOTSUPP, kernel errno 524)";
    case 525: return "Buffer or request too small (ETOOSMALL, kernel errno 525)";
    case 526: return "Server fault (ESERVERFAULT, kernel errno 526)";
    case 527: return "Type not supported (EBADTYPE, kernel errno 527)";
    case 528: return "Try again later (EJUKEBOX, kernel errno 528)";
    case 529: return "I/O queued (EIOCBQUEUED, kernel errno 529)";
    case 530: return "Recall conflict (ERECALLCONFLICT, kernel errno 530)";
    case 531: return "No grace period (ENOGRACE, kernel errno 531)";
    default: break;
    }

    char buf[256];
    buf[0] = '\0';
    const char* msg = strerror_r(err, buf, sizeof(buf));
    return msg ? std::string(msg) : std::string("unknown error");
}

std::string readable_error_message(const std::string& message)
{
    // libbpf's libbpf_strerror_r() falls back to "unknown error (-N)" for
    // errno values glibc cannot translate.  Replace those fragments so a
    // kernel-internal code such as -524 (ENOTSUPP) is readable.
    static const std::string marker = "unknown error (-";
    std::string out;
    size_t pos = 0;

    while (pos < message.size()) {
        const size_t begin = message.find(marker, pos);
        if (begin == std::string::npos) {
            out.append(message, pos, std::string::npos);
            break;
        }
        out.append(message, pos, begin - pos);

        const size_t digits = begin + marker.size();
        size_t end = digits;
        while (end < message.size() && message[end] >= '0' &&
               message[end] <= '9') {
            ++end;
        }
        if (end == digits || end >= message.size() || message[end] != ')') {
            out.append(message, begin, digits - begin);
            pos = digits;
            continue;
        }

        int code = 0;
        bool overflow = false;
        for (size_t i = digits; i < end; ++i) {
            const int digit = message[i] - '0';
            if (code > (INT_MAX - digit) / 10) {
                overflow = true;
                break;
            }
            code = code * 10 + digit;
        }
        if (overflow) {
            out.append(message, begin, end - begin + 1);
            pos = end + 1;
            continue;
        }

        out += errno_string(code);
        pos = end + 1;
    }

    return out;
}

std::string demangle_symbol(const std::string& name)
{
    // Compiler clones such as foo.constprop.0 / foo.isra.0 / foo.part.0 have
    // a valid mangled base followed by a suffix that __cxa_demangle rejects.
    std::string base = name;
    std::string suffix;
    const auto dot = name.find('.');
    if (dot != std::string::npos) {
        base = name.substr(0, dot);
        suffix = name.substr(dot);
    }

    int status = 0;
    char* demangled = abi::__cxa_demangle(base.c_str(), nullptr, nullptr, &status);
    std::string result;
    if (status == 0 && demangled)
        result.assign(demangled);
    else
        result = base;
    std::free(demangled);

    return result + suffix;
}

std::string hex_encode(const uint8_t* data, size_t len)
{
    static const char digits[] = "0123456789abcdef";
    std::string out;
    out.reserve(len * 2);
    for (size_t i = 0; i < len; ++i) {
        out.push_back(digits[data[i] >> 4]);
        out.push_back(digits[data[i] & 0x0f]);
    }
    return out;
}

std::string read_symlink(const std::string& path)
{
    char buf[PATH_MAX];
    const ssize_t n = readlink(path.c_str(), buf, sizeof(buf) - 1);
    if (n < 0)
        fail("readlink %s: %s", path.c_str(), errno_string(errno).c_str());
    buf[n] = '\0';
    return std::string(buf, static_cast<size_t>(n));
}

}  // namespace callgraph
