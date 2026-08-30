// SPDX-License-Identifier: MIT
//
// MiniContainer - Tier 0 foundation: logging.
// Implementation. See include/minicontainer/logging.h for the contract.

#include "minicontainer/logging.h"

#include <sys/time.h>

#include <fcntl.h>
#include <unistd.h>

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <fstream>
#include <iostream>
#include <mutex>
#include <string>

namespace mc {

LogLevel log_level_from_string(std::string_view s) noexcept {
  std::string lower;
  lower.reserve(s.size());
  for (char c : s)
    lower.push_back(
        static_cast<char>(std::tolower(static_cast<unsigned char>(c))));

  if (lower == "trace")
    return LogLevel::Trace;
  if (lower == "debug")
    return LogLevel::Debug;
  if (lower == "info")
    return LogLevel::Info;
  if (lower == "warn" || lower == "warning")
    return LogLevel::Warn;
  if (lower == "error")
    return LogLevel::Error;
  if (lower == "off")
    return LogLevel::Off;
  return LogLevel::Info;
}

const char* log_level_name(LogLevel lvl) noexcept {
  switch (lvl) {
    case LogLevel::Trace:
      return "TRACE";
    case LogLevel::Debug:
      return "DEBUG";
    case LogLevel::Info:
      return "INFO";
    case LogLevel::Warn:
      return "WARN";
    case LogLevel::Error:
      return "ERROR";
    case LogLevel::Off:
      return "OFF";
  }
  return "INFO";
}

namespace {

const char* level_color(LogLevel lvl) noexcept {
  switch (lvl) {
    case LogLevel::Trace:
      return "\x1b[90m";  // bright black / grey
    case LogLevel::Debug:
      return "\x1b[36m";  // cyan
    case LogLevel::Info:
      return "\x1b[32m";  // green
    case LogLevel::Warn:
      return "\x1b[33m";  // yellow
    case LogLevel::Error:
      return "\x1b[31m";  // red
    case LogLevel::Off:
      return "";
  }
  return "";
}
constexpr const char* kColorReset = "\x1b[0m";

// Strips a leading directory path so file names in logs stay short, e.g.
// "/mnt/c/.../cgroup.cpp" -> "cgroup.cpp".
std::string_view basename_view(std::string_view path) noexcept {
  auto pos = path.find_last_of("/\\");
  if (pos == std::string_view::npos)
    return path;
  return path.substr(pos + 1);
}

std::string iso8601_utc_millis() {
  timeval tv{};
  ::gettimeofday(&tv, nullptr);
  std::time_t secs = tv.tv_sec;
  std::tm tm_buf{};
  gmtime_r(&secs, &tm_buf);
  char buf[32];
  std::size_t n = std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%S", &tm_buf);
  int millis = static_cast<int>(tv.tv_usec / 1000);
  char full[40];
  std::snprintf(full, sizeof(full), "%.*s.%03dZ", static_cast<int>(n), buf,
                millis);
  return std::string(full);
}

}  // namespace

struct Logger::Impl {
  std::mutex mtx;
  LogLevel level = LogLevel::Info;
  std::string container_id;
  bool color_enabled = true;
  bool color_forced_off = false;
  std::ofstream out_file;
  bool use_file = false;
};

Logger::Logger() : impl_(new Impl()) {
  impl_->color_enabled = ::isatty(STDERR_FILENO) != 0;
}

Logger::~Logger() {
  delete impl_;
}

Logger& Logger::instance() noexcept {
  static Logger logger;
  return logger;
}

void Logger::set_level(LogLevel lvl) noexcept {
  std::lock_guard<std::mutex> lock(impl_->mtx);
  impl_->level = lvl;
}

LogLevel Logger::level() const noexcept {
  std::lock_guard<std::mutex> lock(impl_->mtx);
  return impl_->level;
}

bool Logger::enabled(LogLevel lvl) const noexcept {
  std::lock_guard<std::mutex> lock(impl_->mtx);
  return impl_->level != LogLevel::Off && lvl >= impl_->level;
}

void Logger::set_container_id(std::string id) noexcept {
  std::lock_guard<std::mutex> lock(impl_->mtx);
  impl_->container_id = std::move(id);
}

void Logger::set_output_file(const std::string& path) noexcept {
  std::lock_guard<std::mutex> lock(impl_->mtx);
  if (path.empty()) {
    impl_->use_file = false;
    if (impl_->out_file.is_open())
      impl_->out_file.close();
    return;
  }
  impl_->out_file.open(path, std::ios::out | std::ios::app);
  impl_->use_file = impl_->out_file.is_open();
}

void Logger::set_color(bool on) noexcept {
  std::lock_guard<std::mutex> lock(impl_->mtx);
  impl_->color_enabled = on;
  impl_->color_forced_off = !on;
}

void Logger::emit(LogLevel lvl, std::string_view file, int line,
                  std::string_view msg) noexcept {
  std::lock_guard<std::mutex> lock(impl_->mtx);
  if (impl_->level == LogLevel::Off || lvl < impl_->level)
    return;

  std::string line_out;
  line_out.reserve(msg.size() + 96);

  line_out += iso8601_utc_millis();
  line_out += ' ';
  line_out += log_level_name(lvl);
  line_out += ' ';
  if (!impl_->container_id.empty()) {
    line_out += '[';
    line_out += impl_->container_id;
    line_out += ']';
    line_out += ' ';
  }
  {
    auto base = basename_view(file);
    line_out.append(base.data(), base.size());
    line_out += ':';
    line_out += std::to_string(line);
    line_out += "  ";
  }
  line_out.append(msg.data(), msg.size());
  line_out += '\n';

  bool use_color = impl_->color_enabled && !impl_->use_file;

  if (impl_->use_file && impl_->out_file.is_open()) {
    impl_->out_file << line_out;
    impl_->out_file.flush();
    return;
  }

  if (use_color) {
    std::cerr << level_color(lvl) << line_out << kColorReset;
  } else {
    std::cerr << line_out;
  }
}

void init_logging_from_env() noexcept {
  const char* env = std::getenv("MINICONTAINER_LOG");
  if (env != nullptr && env[0] != '\0') {
    Logger::instance().set_level(log_level_from_string(env));
  }
}

// ---------------------------------------------------------------------------
// mc::child - async-signal-safe sink. NO malloc, NO locks, NO stdio.
// ---------------------------------------------------------------------------
namespace child {

namespace {
// Not atomic on purpose: set exactly once by the child thread immediately
// after clone(), before any other code runs and before any possibility of
// concurrent access.
int g_log_fd = -1;
}  // namespace

void set_log_fd(int fd) noexcept {
  g_log_fd = fd;
}
int log_fd() noexcept {
  return g_log_fd;
}

void log_raw(const char* msg) noexcept {
  if (g_log_fd < 0 || msg == nullptr)
    return;
  std::size_t len = 0;
  while (msg[len] != '\0')
    ++len;
  (void)::write(g_log_fd, msg, len);
}

void log_raw_n(const char* msg, long n) noexcept {
  if (g_log_fd < 0)
    return;

  // Fixed stack buffer: message text (assumed short/bounded by caller) plus
  // room for a 64-bit decimal integer and a sign. No allocation.
  char buf[256];
  std::size_t pos = 0;

  if (msg != nullptr) {
    std::size_t i = 0;
    while (msg[i] != '\0' && pos < sizeof(buf)) {
      buf[pos++] = msg[i++];
    }
  }

  // Hand-rolled integer-to-decimal conversion (no snprintf).
  unsigned long long mag;
  bool negative = false;
  if (n < 0) {
    negative = true;
    mag = static_cast<unsigned long long>(-(n + 1)) +
          1ULL;  // avoid overflow on LONG_MIN
  } else {
    mag = static_cast<unsigned long long>(n);
  }

  char digits[24];
  int ndigits = 0;
  if (mag == 0) {
    digits[ndigits++] = '0';
  } else {
    while (mag > 0 && ndigits < static_cast<int>(sizeof(digits))) {
      digits[ndigits++] = static_cast<char>('0' + (mag % 10));
      mag /= 10;
    }
  }

  if (negative && pos < sizeof(buf))
    buf[pos++] = '-';
  while (ndigits > 0 && pos < sizeof(buf)) {
    buf[pos++] = digits[--ndigits];
  }

  (void)::write(g_log_fd, buf, pos);
}

}  // namespace child

}  // namespace mc
