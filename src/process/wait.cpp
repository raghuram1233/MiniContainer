// SPDX-License-Identifier: MIT
//
// MiniContainer - process layer: waiting on and signalling container
// processes. See include/minicontainer/process.h for the contract.

#include <sys/syscall.h>
#include <sys/wait.h>

#include <signal.h>
#include <unistd.h>

#include <optional>
#include <sstream>
#include <string>

#include "minicontainer/errors.h"
#include "minicontainer/process.h"
#include "minicontainer/syscall.h"

#ifndef SYS_pidfd_send_signal
#define SYS_pidfd_send_signal 424
#endif

namespace mc {

namespace {

ExitStatus exit_status_from_wait(int status) {
  ExitStatus es;
  if (WIFEXITED(status)) {
    es.exited = true;
    es.code = WEXITSTATUS(status);
  } else if (WIFSIGNALED(status)) {
    es.signaled = true;
    es.signal = WTERMSIG(status);
  }
  return es;
}

}  // namespace

Expected<ExitStatus> wait_for(::pid_t pid) {
  int status = 0;
  for (;;) {
    ::pid_t rv = ::waitpid(pid, &status, 0);
    if (rv < 0) {
      if (errno == EINTR)
        continue;
      return Err(Error::syscall(Op::WaitChild, "waitpid", errno,
                                "pid=" + std::to_string(pid)));
    }
    break;
  }
  return exit_status_from_wait(status);
}

Expected<std::optional<ExitStatus>> try_wait(::pid_t pid) {
  int status = 0;
  for (;;) {
    ::pid_t rv = ::waitpid(pid, &status, WNOHANG);
    if (rv < 0) {
      if (errno == EINTR)
        continue;
      return Err(Error::syscall(Op::WaitChild, "waitpid", errno,
                                "pid=" + std::to_string(pid) + ", WNOHANG"));
    }
    if (rv == 0) {
      // Child exists but has not changed state yet.
      return std::optional<ExitStatus>(std::nullopt);
    }
    break;
  }
  return std::optional<ExitStatus>(exit_status_from_wait(status));
}

int ExitStatus::to_shell_code() const noexcept {
  if (signaled)
    return 128 + signal;
  return code;
}

std::string ExitStatus::describe() const {
  std::ostringstream os;
  if (exited) {
    os << "exited with code " << code;
  } else if (signaled) {
    os << "killed by " << format_signal(signal);
  } else {
    os << "has not exited (unknown wait status)";
  }
  return os.str();
}

Expected<void> signal_process(const Fd& pidfd, ::pid_t fallback_pid, int sig) {
  if (pidfd.valid()) {
    // pidfd_send_signal removes the PID-reuse race: kill(2) targets a raw
    // pid, which by the time we act on a decision to signal may already have
    // been recycled onto an unrelated process. A pidfd stays bound to the
    // exact process (or a closed/invalid state) for its whole lifetime.
    long rv = ::syscall(SYS_pidfd_send_signal, pidfd.get(), sig, nullptr, 0);
    if (rv == 0)
      return Ok();

    int err = errno;
    if (err != ENOSYS) {
      // A real failure (e.g. the process already died -> ESRCH, or we lack
      // permission) - report it rather than silently falling back to a
      // pid-based signal that could hit the wrong process.
      return Err(Error::syscall(Op::SignalChild, "pidfd_send_signal", err,
                                "sig=" + format_signal(sig)));
    }
    // ENOSYS: kernel predates pidfd_send_signal (< 5.1). Fall through to
    // kill(2) below.
  }

  if (::kill(fallback_pid, sig) < 0) {
    return Err(Error::syscall(
        Op::SignalChild, "kill", errno,
        "pid=" + std::to_string(fallback_pid) + ", sig=" + format_signal(sig)));
  }
  return Ok();
}

}  // namespace mc
