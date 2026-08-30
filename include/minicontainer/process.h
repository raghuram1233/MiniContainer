// SPDX-License-Identifier: MIT
//
// MiniContainer - Tier 0 foundation: fds, pipes, and container process launch.
//
// WHY clone3() AND NOT fork()+unshare()
// -------------------------------------
// fork() then unshare(CLONE_NEWPID) does NOT move the caller into the new PID
// namespace - it only arranges for its *children* to be created there. You
// would need a second fork, and in between the process sits half-configured.
// clone3() creates the process directly in every requested namespace in one
// atomic step, with no such window.
//
// clone3() also gives us two things clone() cannot:
//   * CLONE_INTO_CGROUP - the child is born inside its cgroup, so there is no
//     interval where it runs unconfined and could blow past its memory limit
//     before we manage to write its pid into cgroup.procs.
//   * CLONE_PIDFD - a handle immune to PID reuse. Signalling by raw pid always
//     races against that pid being recycled onto an unrelated process.
//
// THE USER-NAMESPACE ORDERING PROBLEM
// -----------------------------------
// With CLONE_NEWUSER the child starts with no valid uid mapping, and until the
// PARENT writes /proc/<pid>/uid_map almost every privileged operation fails.
// Only the parent can write that file, and only once the child exists. So the
// child must block immediately after clone() until it is told the maps are in.
//
// Hence the handshake, over three O_CLOEXEC pipes:
//
//   parent                              child (post-clone)
//   ------                              ------------------
//                                       blocks reading sync pipe
//   write /proc/<pid>/setgroups "deny"
//   write /proc/<pid>/uid_map
//   write /proc/<pid>/gid_map
//   create veth, move peer into netns
//   send 'G' on sync pipe          -->  wakes, runs the setup step table
//                                       on failure: write ChildErrorWire to
//                                         the error pipe, then _exit(127)
//                                       on success: execve()
//   read error pipe:                    (execve closes it, via CLOEXEC)
//     EOF       => container started
//     wire data => reconstruct the Error
//
// setgroups must be denied BEFORE gid_map is written, or the kernel refuses the
// gid_map write outright: keeping setgroups available inside a new user
// namespace would let an unprivileged user DROP supplementary groups and so
// gain access to files protected by a negative group permission.
#pragma once

#include <sys/types.h>

#include <signal.h>

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "minicontainer/errors.h"

namespace mc {

// Move-only RAII file descriptor.
class Fd {
 public:
  Fd() noexcept = default;
  explicit Fd(int fd) noexcept : fd_(fd) {}
  Fd(Fd&& other) noexcept : fd_(other.release()) {}
  Fd& operator=(Fd&& other) noexcept;
  Fd(const Fd&) = delete;
  Fd& operator=(const Fd&) = delete;
  ~Fd() { reset(); }

  [[nodiscard]] int get() const noexcept { return fd_; }
  [[nodiscard]] bool valid() const noexcept { return fd_ >= 0; }
  explicit operator bool() const noexcept { return valid(); }

  [[nodiscard]] int release() noexcept {
    int f = fd_;
    fd_ = -1;
    return f;
  }
  void reset(int fd = -1) noexcept;
  [[nodiscard]] Expected<Fd> duplicate() const;  // sets O_CLOEXEC

 private:
  int fd_ = -1;
};

// A pair of Fds created with O_CLOEXEC.
struct Pipe {
  Fd read_end;
  Fd write_end;

  static Expected<Pipe> create();

  // Blocking read of one byte; nullopt means EOF (the writer closed).
  [[nodiscard]] Expected<std::optional<char>> read_byte();
  [[nodiscard]] Expected<void> write_byte(char c);
};

struct CloneRequest {
  std::uint64_t flags = 0;    // CLONE_NEW* | CLONE_PIDFD | CLONE_INTO_CGROUP
  int exit_signal = SIGCHLD;  // what the parent receives on child death
  int cgroup_fd = -1;         // meaningful only with CLONE_INTO_CGROUP
};

struct CloneResult {
  ::pid_t pid = -1;
  Fd pidfd;  // valid when CLONE_PIDFD was requested
};

// Runs child_fn in a newly cloned process. Returns in the PARENT only - the
// child never returns from here; child_fn must end in execve() or _exit().
//
// child_fn MUST NOT allocate, take a lock, or throw.
using ChildFn = int (*)(void* arg);
Expected<CloneResult> clone_process(const CloneRequest& req, ChildFn child_fn,
                                    void* arg);

// True when the kernel supports clone3 with CLONE_INTO_CGROUP (5.7+). Probed
// once and cached. Without it we fall back to writing cgroup.procs and log that
// the brief unconfined window exists.
bool clone3_into_cgroup_supported() noexcept;

struct ExitStatus {
  bool exited = false;
  bool signaled = false;
  int code = 0;    // exit code, when exited
  int signal = 0;  // terminating signal, when signaled

  // 0-255 for a normal exit, 128+signal when killed - the shell convention.
  [[nodiscard]] int to_shell_code() const noexcept;
  [[nodiscard]] std::string describe() const;
};

Expected<ExitStatus> wait_for(::pid_t pid);
Expected<std::optional<ExitStatus>> try_wait(::pid_t pid);  // WNOHANG

// Prefers pidfd_send_signal, falling back to kill(2). The pidfd path removes
// the PID-reuse race: by the time we decide to send SIGKILL, a raw pid may
// already have been recycled onto an unrelated process.
Expected<void> signal_process(const Fd& pidfd, ::pid_t fallback_pid, int sig);

// PID 1 in a namespace is special in two ways that break naive containers:
//   1. The kernel does not apply DEFAULT signal actions to it. A plain /bin/sh
//      as PID 1 therefore ignores SIGTERM unless it installs a handler, so
//      `minicontainer stop` would hang and fall through to SIGKILL.
//   2. Orphans are reparented to it. If it never reaps them they accumulate as
//      zombies until pids.max is exhausted.
// The shim handles both.
struct InitShimOptions {
  bool forward_signals = true;
  bool reap_orphans = true;
};

// Runs as PID 1 inside the container. Blocks until `child` exits and returns
// its status. Uses signalfd, so signal handling is an ordinary poll loop rather
// than an async-signal-safety minefield.
Expected<ExitStatus> run_init_shim(::pid_t child, const InitShimOptions& opts);

enum class NsType { Pid, Uts, Mount, Ipc, Net, User, Cgroup, Time };
const char* ns_type_name(NsType t) noexcept;
const char* ns_proc_name(NsType t) noexcept;  // "pid", "uts", "mnt", ...

Expected<Fd> open_namespace(::pid_t pid, NsType type);

// setns(2). Order matters: a user namespace must be joined before the
// namespaces it owns, and joining a PID namespace affects only children created
// afterwards - the caller itself stays where it is.
Expected<void> join_namespace(const Fd& ns_fd, NsType type);

}  // namespace mc
