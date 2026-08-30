// SPDX-License-Identifier: MIT
//
// MiniContainer - process layer: the PID-1 init shim.
//
// PID 1 inside a namespace is special in two ways that break a naive
// container entrypoint:
//
//   1. The kernel does not apply DEFAULT signal dispositions to PID 1. An
//      ordinary process that never installs a SIGTERM handler still dies to
//      SIGTERM because the kernel's default action (terminate) applies. PID 1
//      is exempt from that default action, specifically so that a stray
//      SIGTERM sent to init doesn't destroy the whole system by accident. In
//      a container, that protection is exactly backwards: it means
//      `minicontainer stop` sends SIGTERM and the shell running as PID 1
//      simply drops it on the floor, and the caller has to wait out the full
//      SIGKILL timeout every time.
//   2. Orphaned processes are reparented to PID 1 (technically to the nearest
//      surviving ancestor that set PR_SET_CHILD_SUBREAPER, but inside a fresh
//      PID namespace with no subreaper configured, that is PID 1 itself). If
//      PID 1 never calls wait() on them, they finish executing but stay as
//      zombies forever, each pinning a slot in the pid table until
//      pids.max is exhausted and the container can create no new processes.
//
// This shim fixes both: it forwards signals it receives to the tracked
// child's process group (so the child gets the SIGTERM its shell would
// normally have gotten "for free"), and it reaps every reapable child on
// every SIGCHLD, not just the one it is tracking.
//
// signalfd + poll() rather than a signal handler: a traditional handler runs
// asynchronously and can only safely touch a tiny, signal-safe subset of the
// API (see signal-safety(7)). Turning signal delivery into a readable fd
// turns "handle a signal" into an ordinary poll loop, so the reaping and
// forwarding logic below is plain, ordered, non-reentrant code.

#include <sys/signalfd.h>
#include <sys/wait.h>

#include <poll.h>
#include <signal.h>
#include <unistd.h>

#include <cerrno>
#include <optional>

#include "minicontainer/errors.h"
#include "minicontainer/process.h"

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

Expected<ExitStatus> run_init_shim(::pid_t child, const InitShimOptions& opts) {
  sigset_t full_set;
  ::sigfillset(&full_set);

  // Block every signal on this thread first: signalfd only delivers signals
  // that are blocked (otherwise the kernel's default/handler disposition
  // fires instead of queuing them for the fd). SIGKILL/SIGSTOP cannot be
  // blocked; the kernel silently ignores them in the mask, which is fine -
  // nothing can catch or forward those anyway.
  if (::sigprocmask(SIG_BLOCK, &full_set, nullptr) < 0) {
    return Err(Error::syscall(Op::Internal, "sigprocmask", errno, "SIG_BLOCK"));
  }

  Fd sfd(::signalfd(-1, &full_set, SFD_CLOEXEC));
  if (!sfd.valid()) {
    return Err(Error::syscall(Op::Internal, "signalfd", errno, ""));
  }

  // Put the tracked child in a process group of its own, led by itself, so
  // that the kill(-child, ...) below has a group to address. Nothing else
  // creates it: a clone3() child inherits its parent's pgid, so without this
  // `-child` names a group that does not exist and every forwarded signal
  // fails with ESRCH - silently, since kill()'s return value is the only
  // evidence and there is nobody to report it to.
  //
  // Doing it from this side races with the child doing it for itself, which
  // is harmless: both calls set the same pgid, and the standard idiom is for
  // both sides to try. EACCES means the child already execve'd, by which
  // point it has whatever group it chose, so a failure here is not fatal -
  // the forwarding path falls back to signalling the child directly.
  if (opts.forward_signals) {
    ::setpgid(child, child);
  }

  std::optional<ExitStatus> tracked_status;

  while (!tracked_status.has_value()) {
    struct ::pollfd pfd {};
    pfd.fd = sfd.get();
    pfd.events = POLLIN;

    int prv = ::poll(&pfd, 1, -1);
    if (prv < 0) {
      if (errno == EINTR)
        continue;
      return Err(Error::syscall(Op::Internal, "poll", errno, ""));
    }
    if (prv == 0 || !(pfd.revents & POLLIN))
      continue;

    struct ::signalfd_siginfo si {};
    ssize_t n = ::read(sfd.get(), &si, sizeof(si));
    if (n != static_cast<ssize_t>(sizeof(si))) {
      // Short read / EINTR / spurious wakeup: just poll again.
      continue;
    }

    int signo = static_cast<int>(si.ssi_signo);

    if (signo == SIGCHLD) {
      // Reap every child that is ready, not just the one we are tracking -
      // that is what prevents reparented orphans from piling up as zombies.
      // Never forward SIGCHLD itself; it is consumed here.
      if (opts.reap_orphans) {
        for (;;) {
          int status = 0;
          ::pid_t rv = ::waitpid(-1, &status, WNOHANG);
          if (rv <= 0)
            break;  // 0: nothing else ready; -1 (ECHILD): none left
          if (rv == child) {
            tracked_status = exit_status_from_wait(status);
          }
        }
      } else {
        // Orphan reaping disabled, but we must still reap our own tracked
        // child specifically, or run_init_shim would block forever.
        int status = 0;
        ::pid_t rv = ::waitpid(child, &status, WNOHANG);
        if (rv == child) {
          tracked_status = exit_status_from_wait(status);
        }
      }
      continue;
    }

    if (opts.forward_signals) {
      // Forward to the tracked child's process GROUP, not just the child
      // pid: a container entrypoint like `sh -c 'sleep 100'` spawns sleep as
      // a separate process in the same group, and kill(child, sig) alone
      // would leave sleep running after sh exits.
      //
      // If the group does not exist - the setpgid above lost its race with an
      // execve, or the child moved itself elsewhere - fall back to the child
      // alone. Delivering the signal to one process beats delivering it to
      // none, which is what a bare kill(-child, ...) would do here.
      if (::kill(-child, signo) < 0 && errno == ESRCH) {
        ::kill(child, signo);
      }
    }
  }

  return tracked_status.value();
}

}  // namespace mc
