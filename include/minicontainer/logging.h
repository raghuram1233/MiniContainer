// SPDX-License-Identifier: MIT
//
// MiniContainer - Tier 0 foundation: logging.
//
// TWO SINKS, DELIBERATELY DISJOINT
// --------------------------------
// Parent side (MC_LOG_*): formats with std::ostringstream, takes a mutex,
// allocates. Perfectly normal, and completely forbidden after clone().
//
// Child side (MC_CLOG_*): between clone() and execve() the process may hold a
// malloc lock inherited from a thread that no longer exists in this address
// space, so a single allocation can deadlock forever. Worse, taking the
// logger's mutex is the same hazard. The child sink therefore does exactly one
// thing: write(2) a preformatted byte range to a preserved fd. No allocation,
// no locks, async-signal-safe.
//
// This split is enforced mechanically in CI: MC_LOG_* must not appear anywhere
// under src/child/. See scripts/check-child-purity.sh.
#pragma once

#include <cstdint>
#include <sstream>
#include <string>
#include <string_view>

namespace mc {

enum class LogLevel : int {
  Trace = 0,
  Debug = 1,
  Info = 2,
  Warn = 3,
  Error = 4,
  Off = 5,
};

// Parses "trace"|"debug"|"info"|"warn"|"error"|"off", case-insensitive.
// Returns LogLevel::Info for anything unrecognised.
LogLevel log_level_from_string(std::string_view s) noexcept;
const char* log_level_name(LogLevel lvl) noexcept;

// Process-wide logger. Configured once from MINICONTAINER_LOG (env) or
// --log-level.
class Logger {
 public:
  static Logger& instance() noexcept;

  void set_level(LogLevel lvl) noexcept;
  [[nodiscard]] LogLevel level() const noexcept;
  [[nodiscard]] bool enabled(LogLevel lvl) const noexcept;

  // Emit one already-formatted record. Adds timestamp, level, and the
  // container id if one has been set. Thread-safe.
  void emit(LogLevel lvl, std::string_view file, int line,
            std::string_view msg) noexcept;

  // Tags every subsequent line, so interleaved container logs stay readable.
  void set_container_id(std::string id) noexcept;

  // Redirect records to a file (used by `minicontainer logs`). Empty = stderr.
  void set_output_file(const std::string& path) noexcept;

  // Colour is auto-disabled when stderr is not a TTY.
  void set_color(bool on) noexcept;

 private:
  Logger();
  ~Logger();
  Logger(const Logger&) = delete;
  Logger& operator=(const Logger&) = delete;
  struct Impl;
  Impl* impl_;
};

// Reads MINICONTAINER_LOG and applies it. Call once from main().
void init_logging_from_env() noexcept;

}  // namespace mc

// ---------------------------------------------------------------------------
// Parent-side macros. The `if (enabled)` guard keeps the stream construction
// out of the hot path when the level is disabled.
// ---------------------------------------------------------------------------
#define MC_LOG_AT(lvl, ...)                                                   \
  do {                                                                        \
    if (::mc::Logger::instance().enabled(lvl)) {                              \
      std::ostringstream _mc_os;                                              \
      _mc_os << __VA_ARGS__;                                                  \
      ::mc::Logger::instance().emit((lvl), __FILE__, __LINE__, _mc_os.str()); \
    }                                                                         \
  } while (0)

#define MC_LOG_TRACE(...) MC_LOG_AT(::mc::LogLevel::Trace, __VA_ARGS__)
#define MC_LOG_DEBUG(...) MC_LOG_AT(::mc::LogLevel::Debug, __VA_ARGS__)
#define MC_LOG_INFO(...) MC_LOG_AT(::mc::LogLevel::Info, __VA_ARGS__)
#define MC_LOG_WARN(...) MC_LOG_AT(::mc::LogLevel::Warn, __VA_ARGS__)
#define MC_LOG_ERROR(...) MC_LOG_AT(::mc::LogLevel::Error, __VA_ARGS__)

namespace mc::child {

// Set by the child immediately after clone(), before any other work.
// -1 disables child logging entirely.
void set_log_fd(int fd) noexcept;
[[nodiscard]] int log_fd() noexcept;

// async-signal-safe: a single write(2) of a NUL-terminated literal plus an
// optional integer. Never allocates, never locks. `n` is appended in decimal
// when append_number is true (used for errno and step indices).
void log_raw(const char* msg) noexcept;
void log_raw_n(const char* msg, long n) noexcept;

}  // namespace mc::child

// Child-side macros. Only string literals and integers - by construction there
// is nothing here that can allocate.
#define MC_CLOG(msg) ::mc::child::log_raw(msg)
#define MC_CLOG_N(msg, n) ::mc::child::log_raw_n((msg), (n))
