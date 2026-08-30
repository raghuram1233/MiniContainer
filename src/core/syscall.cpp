// SPDX-License-Identifier: MIT
//
// MiniContainer - Tier 0 foundation: thin syscall wrappers and flag decoding.
// Implementation. See include/minicontainer/syscall.h for the contract.

#include "minicontainer/syscall.h"

#include <linux/sched.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <unistd.h>

#include <climits>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <utility>

#include "minicontainer/logging.h"

namespace mc {

// ---------------------------------------------------------------------------
// format_clone_flags
// ---------------------------------------------------------------------------
namespace {
struct FlagEntry {
  std::uint64_t bit;
  const char* name;
};

// clang-format off
constexpr FlagEntry kCloneFlags[] = {
    {static_cast<std::uint64_t>(CLONE_NEWPID), "CLONE_NEWPID"},
    {static_cast<std::uint64_t>(CLONE_NEWUTS), "CLONE_NEWUTS"},
    {static_cast<std::uint64_t>(CLONE_NEWNS), "CLONE_NEWNS"},
    {static_cast<std::uint64_t>(CLONE_NEWIPC), "CLONE_NEWIPC"},
    {static_cast<std::uint64_t>(CLONE_NEWNET), "CLONE_NEWNET"},
    {static_cast<std::uint64_t>(CLONE_NEWUSER), "CLONE_NEWUSER"},
    {static_cast<std::uint64_t>(CLONE_NEWCGROUP), "CLONE_NEWCGROUP"},
    {static_cast<std::uint64_t>(CLONE_NEWTIME), "CLONE_NEWTIME"},
    {static_cast<std::uint64_t>(CLONE_PIDFD), "CLONE_PIDFD"},
    {static_cast<std::uint64_t>(CLONE_INTO_CGROUP), "CLONE_INTO_CGROUP"},
    {static_cast<std::uint64_t>(CLONE_VM), "CLONE_VM"},
    {static_cast<std::uint64_t>(CLONE_FS), "CLONE_FS"},
    {static_cast<std::uint64_t>(CLONE_FILES), "CLONE_FILES"},
    {static_cast<std::uint64_t>(CLONE_SIGHAND), "CLONE_SIGHAND"},
    {static_cast<std::uint64_t>(CLONE_VFORK), "CLONE_VFORK"},
    {static_cast<std::uint64_t>(CLONE_PARENT), "CLONE_PARENT"},
    {static_cast<std::uint64_t>(CLONE_THREAD), "CLONE_THREAD"},
};

constexpr FlagEntry kMountFlags[] = {
    {static_cast<std::uint64_t>(MS_RDONLY), "MS_RDONLY"},
    {static_cast<std::uint64_t>(MS_NOSUID), "MS_NOSUID"},
    {static_cast<std::uint64_t>(MS_NODEV), "MS_NODEV"},
    {static_cast<std::uint64_t>(MS_NOEXEC), "MS_NOEXEC"},
    {static_cast<std::uint64_t>(MS_SYNCHRONOUS), "MS_SYNCHRONOUS"},
    {static_cast<std::uint64_t>(MS_REMOUNT), "MS_REMOUNT"},
    {static_cast<std::uint64_t>(MS_MANDLOCK), "MS_MANDLOCK"},
    {static_cast<std::uint64_t>(MS_DIRSYNC), "MS_DIRSYNC"},
    {static_cast<std::uint64_t>(MS_NOATIME), "MS_NOATIME"},
    {static_cast<std::uint64_t>(MS_NODIRATIME), "MS_NODIRATIME"},
    {static_cast<std::uint64_t>(MS_BIND), "MS_BIND"},
    {static_cast<std::uint64_t>(MS_MOVE), "MS_MOVE"},
    {static_cast<std::uint64_t>(MS_REC), "MS_REC"},
    {static_cast<std::uint64_t>(MS_SILENT), "MS_SILENT"},
    {static_cast<std::uint64_t>(MS_POSIXACL), "MS_POSIXACL"},
    {static_cast<std::uint64_t>(MS_UNBINDABLE), "MS_UNBINDABLE"},
    {static_cast<std::uint64_t>(MS_PRIVATE), "MS_PRIVATE"},
    {static_cast<std::uint64_t>(MS_SLAVE), "MS_SLAVE"},
    {static_cast<std::uint64_t>(MS_SHARED), "MS_SHARED"},
    {static_cast<std::uint64_t>(MS_RELATIME), "MS_RELATIME"},
    {static_cast<std::uint64_t>(MS_STRICTATIME), "MS_STRICTATIME"},
    {static_cast<std::uint64_t>(MS_LAZYTIME), "MS_LAZYTIME"},
};
// clang-format on

std::string format_bits(std::uint64_t flags, const FlagEntry* table,
                        std::size_t table_len) {
  if (flags == 0)
    return "0";
  std::string out;
  std::uint64_t remaining = flags;
  for (std::size_t i = 0; i < table_len; ++i) {
    if (remaining & table[i].bit) {
      if (!out.empty())
        out += '|';
      out += table[i].name;
      remaining &= ~table[i].bit;
    }
  }
  if (remaining != 0) {
    if (!out.empty())
      out += '|';
    char buf[24];
    std::snprintf(buf, sizeof(buf), "0x%llx",
                  static_cast<unsigned long long>(remaining));
    out += buf;
  }
  return out;
}

}  // namespace

std::string format_clone_flags(std::uint64_t flags) {
  return format_bits(flags, kCloneFlags,
                     sizeof(kCloneFlags) / sizeof(kCloneFlags[0]));
}

std::string format_mount_flags(unsigned long flags) {
  return format_bits(static_cast<std::uint64_t>(flags), kMountFlags,
                     sizeof(kMountFlags) / sizeof(kMountFlags[0]));
}

std::string format_signal(int sig) {
  static constexpr std::pair<int, const char*> kSignals[] = {
      {SIGHUP, "SIGHUP"},       {SIGINT, "SIGINT"},       {SIGQUIT, "SIGQUIT"},
      {SIGILL, "SIGILL"},       {SIGTRAP, "SIGTRAP"},     {SIGABRT, "SIGABRT"},
      {SIGBUS, "SIGBUS"},       {SIGFPE, "SIGFPE"},       {SIGKILL, "SIGKILL"},
      {SIGUSR1, "SIGUSR1"},     {SIGSEGV, "SIGSEGV"},     {SIGUSR2, "SIGUSR2"},
      {SIGPIPE, "SIGPIPE"},     {SIGALRM, "SIGALRM"},     {SIGTERM, "SIGTERM"},
      {SIGSTKFLT, "SIGSTKFLT"}, {SIGCHLD, "SIGCHLD"},     {SIGCONT, "SIGCONT"},
      {SIGSTOP, "SIGSTOP"},     {SIGTSTP, "SIGTSTP"},     {SIGTTIN, "SIGTTIN"},
      {SIGTTOU, "SIGTTOU"},     {SIGURG, "SIGURG"},       {SIGXCPU, "SIGXCPU"},
      {SIGXFSZ, "SIGXFSZ"},     {SIGVTALRM, "SIGVTALRM"}, {SIGPROF, "SIGPROF"},
      {SIGWINCH, "SIGWINCH"},   {SIGIO, "SIGIO"},         {SIGPWR, "SIGPWR"},
      {SIGSYS, "SIGSYS"},
  };
  for (const auto& [n, name] : kSignals) {
    if (n == sig)
      return name;
  }
  return "SIG" + std::to_string(sig);
}

Expected<std::uint64_t> clone_flag_from_name(std::string_view name) {
  static constexpr std::pair<std::string_view, std::uint64_t> kMap[] = {
      {"CLONE_NEWPID", static_cast<std::uint64_t>(CLONE_NEWPID)},
      {"CLONE_NEWUTS", static_cast<std::uint64_t>(CLONE_NEWUTS)},
      {"CLONE_NEWNS", static_cast<std::uint64_t>(CLONE_NEWNS)},
      {"CLONE_NEWIPC", static_cast<std::uint64_t>(CLONE_NEWIPC)},
      {"CLONE_NEWNET", static_cast<std::uint64_t>(CLONE_NEWNET)},
      {"CLONE_NEWUSER", static_cast<std::uint64_t>(CLONE_NEWUSER)},
      {"CLONE_NEWCGROUP", static_cast<std::uint64_t>(CLONE_NEWCGROUP)},
      {"CLONE_NEWTIME", static_cast<std::uint64_t>(CLONE_NEWTIME)},
  };
  for (const auto& [n, bit] : kMap) {
    if (n == name)
      return bit;
  }
  return Err(Error::invalid(
      Op::ParseConfig, "unknown namespace flag: '" + std::string(name) + "'"));
}

// ---------------------------------------------------------------------------
// Small filesystem helpers.
// ---------------------------------------------------------------------------
Expected<std::string> read_file(const std::string& path, Op op) {
  int fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    return Err(Error::syscall(op, "open", errno, path));
  }

  std::string content;
  char buf[4096];
  for (;;) {
    ssize_t n = ::read(fd, buf, sizeof(buf));
    if (n < 0) {
      int err = errno;
      ::close(fd);
      return Err(Error::syscall(op, "read", err, path));
    }
    if (n == 0)
      break;  // EOF
    content.append(buf, static_cast<std::size_t>(n));
  }
  ::close(fd);
  return content;
}

Expected<void> write_file(const std::string& path, std::string_view content,
                          Op op) {
  int fd = ::open(path.c_str(), O_WRONLY | O_CLOEXEC);
  if (fd < 0) {
    return Err(Error::syscall(op, "open", errno, path));
  }

  ssize_t n = ::write(fd, content.data(), content.size());
  int err = (n < 0) ? errno : 0;
  ::close(fd);

  if (n < 0) {
    return Err(Error::syscall(op, "write", err, path));
  }
  if (static_cast<std::size_t>(n) != content.size()) {
    return Err(Error::syscall(op, "write", 0,
                              path + ": short write (" + std::to_string(n) +
                                  "/" + std::to_string(content.size()) +
                                  " bytes)"));
  }
  return Ok();
}

Expected<void> make_directories(const std::string& path, Op op) {
  if (path.empty()) {
    return Err(Error::invalid(op, "empty path"));
  }

  std::string cur;
  std::size_t i = 0;
  if (path[0] == '/') {
    cur = "/";
    i = 1;
  }

  while (i <= path.size()) {
    std::size_t next = path.find('/', i);
    std::size_t end = (next == std::string::npos) ? path.size() : next;
    std::string component = path.substr(i, end - i);

    if (!component.empty()) {
      if (!cur.empty() && cur.back() != '/')
        cur += '/';
      cur += component;

      if (::mkdir(cur.c_str(), 0755) < 0) {
        if (errno != EEXIST) {
          return Err(Error::syscall(op, "mkdir", errno, cur));
        }
        struct stat st {};
        if (::stat(cur.c_str(), &st) < 0 || !S_ISDIR(st.st_mode)) {
          return Err(Error::syscall(op, "mkdir", EEXIST,
                                    cur + ": exists and is not a directory"));
        }
      }
    }

    if (next == std::string::npos)
      break;
    i = next + 1;
  }
  return Ok();
}

Expected<void> write_file_atomic(const std::string& path,
                                 std::string_view content, Op op) {
  std::string tmp = path + ".tmp." + std::to_string(::getpid());

  int fd = ::open(tmp.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
  if (fd < 0) {
    return Err(Error::syscall(op, "open", errno, tmp));
  }

  ssize_t n = ::write(fd, content.data(), content.size());
  if (n < 0 || static_cast<std::size_t>(n) != content.size()) {
    int err = (n < 0) ? errno : 0;
    ::close(fd);
    ::unlink(tmp.c_str());
    if (n < 0)
      return Err(Error::syscall(op, "write", err, tmp));
    return Err(Error::syscall(op, "write", 0, tmp + ": short write"));
  }

  if (::fsync(fd) < 0) {
    int err = errno;
    ::close(fd);
    ::unlink(tmp.c_str());
    return Err(Error::syscall(op, "fsync", err, tmp));
  }

  if (::close(fd) < 0) {
    int err = errno;
    ::unlink(tmp.c_str());
    return Err(Error::syscall(op, "close", err, tmp));
  }

  if (::rename(tmp.c_str(), path.c_str()) < 0) {
    int err = errno;
    ::unlink(tmp.c_str());
    return Err(Error::syscall(op, "rename", err, tmp + " -> " + path));
  }

  // Best-effort: fsync the containing directory so the rename survives a
  // crash. The rename itself already succeeded, so a failure here is not
  // reported as an overall failure of the write.
  std::string dir;
  auto slash = path.find_last_of('/');
  if (slash == std::string::npos) {
    dir = ".";
  } else if (slash == 0) {
    dir = "/";
  } else {
    dir = path.substr(0, slash);
  }
  int dfd = ::open(dir.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
  if (dfd >= 0) {
    if (::fsync(dfd) < 0) {
      MC_LOG_WARN("write_file_atomic: fsync("
                  << dir << ") failed: " << std::strerror(errno));
    }
    ::close(dfd);
  }

  return Ok();
}

bool is_directory(const std::string& path) noexcept {
  struct stat st {};
  if (::stat(path.c_str(), &st) < 0)
    return false;
  return S_ISDIR(st.st_mode);
}

bool path_exists(const std::string& path) noexcept {
  struct stat st {};
  return ::stat(path.c_str(), &st) == 0;
}

Expected<std::string> canonicalize(const std::string& path, Op op) {
  char buf[PATH_MAX];
  if (::realpath(path.c_str(), buf) == nullptr) {
    return Err(Error::syscall(op, "realpath", errno, path));
  }
  return std::string(buf);
}

}  // namespace mc
