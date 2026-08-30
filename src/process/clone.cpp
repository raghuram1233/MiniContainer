// SPDX-License-Identifier: MIT
//
// MiniContainer - process layer: clone3()-based container process creation.
// See include/minicontainer/process.h for the design rationale (the long
// comment at the top of that file explains why clone3 and not fork+unshare,
// and why the uid_map handshake exists). This is the single most dangerous
// file in the project: everything here runs on the thin sliver of process
// state between clone() and execve()/{_exit()}.

#include <sys/syscall.h>
#include <sys/utsname.h>
#include <sys/vfs.h>

#include <sched.h>
#include <unistd.h>

#include <cstdint>
#include <cstdio>
#include <string>

#include "minicontainer/errors.h"
#include "minicontainer/logging.h"
#include "minicontainer/process.h"
#include "minicontainer/syscall.h"

// CLONE_INTO_CGROUP is not exposed by glibc's <sched.h> on Ubuntu 24.04
// (glibc 2.39), even though the kernel UAPI (<linux/sched.h>) has carried it
// since 5.7. We deliberately do NOT #include <linux/sched.h> here: it
// redefines struct sched_param and clashes with glibc's <sched.h> on some
// toolchains. Defining the bit ourselves, guarded, is the documented
// workaround (see process.h and the task brief for this file).
#ifndef CLONE_INTO_CGROUP
#define CLONE_INTO_CGROUP 0x200000000ULL
#endif
#ifndef CLONE_PIDFD
#define CLONE_PIDFD 0x00001000
#endif
#ifndef CLONE_NEWTIME
#define CLONE_NEWTIME 0x00000080
#endif

#ifndef SYS_clone3
#define SYS_clone3 435
#endif

namespace mc {

namespace {

// clone_args as specified by the clone3(2) UAPI (struct clone_args in
// <linux/sched.h>, CLONE_ARGS_SIZE_VER2). Declared locally rather than
// pulling in <linux/sched.h> - see the comment above on the sched.h clash.
// glibc does not wrap clone3() at all (checked: glibc 2.39 on Ubuntu 24.04),
// so the raw syscall is the only way to reach it.
struct clone_args_local {
  std::uint64_t flags;
  std::uint64_t pidfd;
  std::uint64_t child_tid;
  std::uint64_t parent_tid;
  std::uint64_t exit_signal;
  std::uint64_t stack;
  std::uint64_t stack_size;
  std::uint64_t tls;
  std::uint64_t set_tid;
  std::uint64_t set_tid_size;
  std::uint64_t cgroup;
};

long raw_clone3(clone_args_local* args) {
  return ::syscall(SYS_clone3, args, sizeof(*args));
}

}  // namespace

Expected<CloneResult> clone_process(const CloneRequest& req, ChildFn child_fn,
                                    void* arg) {
  if (req.flags & CLONE_INTO_CGROUP) {
    if (req.cgroup_fd < 0) {
      return Err(Error::invalid(
          Op::CloneProcess,
          "CLONE_INTO_CGROUP requested but cgroup_fd is not set"));
    }
  }

  clone_args_local args{};
  args.flags = req.flags;
  args.exit_signal = static_cast<std::uint64_t>(req.exit_signal);

  // clone3 with stack == 0 makes the child return from the syscall exactly
  // like fork() does - the kernel allocates its stack for us. We never need
  // to hand it a child stack the way raw clone(2) requires.
  args.stack = 0;
  args.stack_size = 0;

  // The kernel writes a 32-bit pidfd into this address post-clone; the field
  // itself is a u64 (so it also works on 32-bit userspace), but what it
  // points to is a plain int.
  int pidfd_storage = -1;
  if (req.flags & CLONE_PIDFD) {
    args.pidfd = reinterpret_cast<std::uint64_t>(&pidfd_storage);
  }

  if (req.flags & CLONE_INTO_CGROUP) {
    args.cgroup = static_cast<std::uint64_t>(req.cgroup_fd);
  }

  long rv = raw_clone3(&args);
  if (rv < 0) {
    int err = errno;

    if (err == ENOSYS) {
      return Err(Error::unsupported(
          Op::CloneProcess, "clone3(2) is not implemented by this kernel"));
    }

    std::string detail = format_clone_flags(req.flags);
    if (err == EPERM) {
      detail +=
          "; EPERM here usually means missing CAP_SYS_ADMIN, or unprivileged "
          "user namespaces are disabled "
          "(check /proc/sys/kernel/unprivileged_userns_clone)";
    } else if (err == EUSERS) {
      detail +=
          "; EUSERS means /proc/sys/user/max_user_namespaces is 0, or the "
          "per-user nested user-namespace limit was hit";
    }
    return Err(Error::syscall(Op::CloneProcess, "clone3", err, detail));
  }

  if (rv == 0) {
    // We are the child. clone3() with a null stack returns here exactly like
    // fork() would. child_fn must end in execve() or _exit(); if it somehow
    // returns instead, treat that as a bug and exit rather than falling back
    // into whatever the parent was doing.
    int child_rv = child_fn(arg);
    _exit(child_rv);
  }

  // Parent.
  CloneResult result;
  result.pid = static_cast<::pid_t>(rv);
  if (req.flags & CLONE_PIDFD) {
    result.pidfd = Fd(pidfd_storage);
  }
  return result;
}

bool clone3_into_cgroup_supported() noexcept {
  // HONEST HEURISTIC, not a real probe: actually verifying CLONE_INTO_CGROUP
  // support would mean calling clone3() with a real cgroup fd and a live
  // process, which is exactly the invasive, hard-to-undo operation this
  // function exists to let callers avoid before they commit to it. Instead we
  // infer support from two independent, cheap facts:
  //
  //   1. The running kernel is >= 5.7, the version that introduced
  //      CLONE_INTO_CGROUP.
  //   2. /sys/fs/cgroup is mounted as cgroup2 (cgroup v1 has no per-process
  //      "into cgroup" concept at clone time; CLONE_INTO_CGROUP only makes
  //      sense against a unified v2 hierarchy).
  //
  // This can be wrong in adversarial setups (a custom kernel that backports
  // the flag, or a mixed v1/v2 mount layout), which is why callers should
  // still treat a clone3() failure with CLONE_INTO_CGROUP as recoverable and
  // fall back to writing cgroup.procs after the fact.
  static const bool kSupported = [] {
    struct ::utsname uts {};
    if (::uname(&uts) != 0)
      return false;

    int major = 0;
    int minor = 0;
    if (::sscanf(uts.release, "%d.%d", &major, &minor) != 2)
      return false;
    bool kernel_ok = (major > 5) || (major == 5 && minor >= 7);
    if (!kernel_ok)
      return false;

    struct ::statfs sfs {};
    if (::statfs("/sys/fs/cgroup", &sfs) != 0)
      return false;
    constexpr long kCgroup2SuperMagic =
        0x63677270;  // "cgrp" -> CGROUP2_SUPER_MAGIC
    return sfs.f_type == kCgroup2SuperMagic;
  }();
  return kSupported;
}

}  // namespace mc
