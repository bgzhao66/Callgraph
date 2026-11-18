#pragma once

#include <csignal>
#include <cstdint>
#include <cstdio>
#include <stdexcept>
#include <string>

namespace callgraph {

enum class LogLevel { Quiet, Normal, Verbose };
extern LogLevel g_log_level;

// Set by the signal handler and polled by the collector.
extern volatile sig_atomic_t g_stop;

// Prefix used by log_* and by the CLI's top-level error reporter.  Defaults to
// "callgraph"; each executable sets its own name.
void set_program_name(const char* name);
const char* program_name();

class Error : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

[[noreturn]] void fail(const char* fmt, ...) __attribute__((format(printf, 1, 2)));
void log_warn(const char* fmt, ...) __attribute__((format(printf, 1, 2)));
void log_info(const char* fmt, ...) __attribute__((format(printf, 1, 2)));
void log_verbose(const char* fmt, ...) __attribute__((format(printf, 1, 2)));

std::string errno_string(int err);
// Rewrites libbpf's opaque "unknown error (-N)" fragments into readable names
// for kernel-internal errno values.
std::string readable_error_message(const std::string& message);

// Deterministic 64-bit mixer used by sampling and identifier generation.
uint64_t splitmix64(uint64_t value);

std::string demangle_symbol(const std::string& name);
std::string hex_encode(const uint8_t* data, size_t len);
std::string read_symlink(const std::string& path);

}  // namespace callgraph
