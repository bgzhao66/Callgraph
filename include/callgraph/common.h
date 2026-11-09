#pragma once

#include <cstdint>
#include <cstdio>
#include <stdexcept>
#include <string>

namespace callgraph {

enum class LogLevel { Quiet, Normal, Verbose };
extern LogLevel g_log_level;

class Error : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

[[noreturn]] void fail(const char* fmt, ...) __attribute__((format(printf, 1, 2)));
void log_warn(const char* fmt, ...) __attribute__((format(printf, 1, 2)));
void log_info(const char* fmt, ...) __attribute__((format(printf, 1, 2)));
void log_verbose(const char* fmt, ...) __attribute__((format(printf, 1, 2)));

std::string errno_string(int err);
std::string demangle_symbol(const std::string& name);
std::string hex_encode(const uint8_t* data, size_t len);
std::string read_symlink(const std::string& path);

}  // namespace callgraph
