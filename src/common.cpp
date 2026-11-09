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
    char buf[256];
    buf[0] = '\0';
    const char* msg = strerror_r(err, buf, sizeof(buf));
    return msg ? std::string(msg) : std::string("unknown error");
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
