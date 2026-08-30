// SPDX-License-Identifier: MIT
//
// MiniContainer - no_new_privs and seccomp filter installation.
//
// THE SPLIT THIS FILE EXISTS TO ENFORCE
// -------------------------------------
// libseccomp is an ordinary allocating library: seccomp_init() mallocs, and
// building a rule set allocates repeatedly. None of that can happen in the
// child, where a malloc may deadlock forever on a lock inherited from a thread
// that no longer exists.
//
// So the profile is compiled to raw BPF in the PARENT, stored as a flat byte
// array in ChildContext, and the child installs it with one bare syscall. The
// child-side half of this file is therefore about ten lines, and that is the
// point.
//
// WHY no_new_privs MUST COME FIRST
// --------------------------------
// seccomp(SECCOMP_SET_MODE_FILTER) requires either CAP_SYS_ADMIN or
// no_new_privs. We drop CAP_SYS_ADMIN precisely because a container should not
// have it, so no_new_privs is the only route left - and it must be set before
// the filter goes on, or the filter call returns EACCES. The step table
// encodes that order; this comment is why it is not negotiable.
//
// no_new_privs is load-bearing on its own too: it makes execve() refuse to
// grant privileges through a setuid binary, which is what stops a container
// process from regaining root by running something like /usr/bin/passwd.
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sys/prctl.h>
#include <sys/syscall.h>

#include <errno.h>
#include <unistd.h>

#include <cstddef>
#include <cstring>
#include <string>

#include "minicontainer/container.h"
#include "minicontainer/errors.h"
#include "minicontainer/process.h"
#include "minicontainer/security.h"

#if MC_ENABLE_SECCOMP
#include <fcntl.h>
#include <seccomp.h>

#include <vector>
#endif

namespace mc {

bool seccomp_available() noexcept {
#if MC_ENABLE_SECCOMP
  return true;
#else
  return false;
#endif
}

#if MC_ENABLE_SECCOMP
namespace {

// The deny list. Every entry either reconfigures the host, escapes the
// sandbox, or loads code into the kernel - none of which an ordinary
// containerised program needs.
//
// A deny list is the weaker choice: an allow list cannot be bypassed by a
// syscall nobody thought of. It is used here because an allow list has to
// enumerate the several hundred syscalls a libc actually makes, varies by
// architecture and libc version, and breaks programs in ways that look like
// bugs in the program. For a teaching runtime, a deny list that visibly blocks
// the dangerous operations is the more honest trade - and this comment is the
// place that says so, rather than letting the choice look accidental.
struct DeniedSyscall {
  const char* name;
  int number;
};

std::vector<DeniedSyscall> denied_syscalls() {
  // Resolved by name, so a syscall that does not exist on this architecture is
  // skipped rather than aborting the whole profile.
  static const char* const kNames[] = {
      // Mount and root manipulation: setup is already done; there is no
      // legitimate reason for the container to remount anything.
      "mount",
      "umount",
      "umount2",
      "pivot_root",
      "chroot",
      "move_mount",
      "open_tree",
      "fsopen",
      "fsconfig",
      "fsmount",
      // Kernel module loading - straightforward host compromise.
      "init_module",
      "finit_module",
      "delete_module",
      // Reboot and kexec: host-wide effects from inside a container.
      "reboot",
      "kexec_load",
      "kexec_file_load",
      // Swap reconfiguration.
      "swapon",
      "swapoff",
      // Namespace escape and cross-process inspection.
      "setns",
      "unshare",
      "ptrace",
      "process_vm_readv",
      "process_vm_writev",
      // Kernel keyring: shared across the host.
      "add_key",
      "keyctl",
      "request_key",
      // Loading kernel programs / arbitrary tracing.
      "bpf",
      "perf_event_open",
      // Fault handling usable to win TOCTOU races against the kernel.
      "userfaultfd",
      // Filehandle-based path resolution, which can reach outside the rootfs.
      "name_to_handle_at",
      "open_by_handle_at",
      // Host-wide clock and identity.
      "clock_settime",
      "clock_adjtime",
      "settimeofday",
      "adjtimex",
      "sethostname",
      "setdomainname",
      // Direct hardware access.
      "iopl",
      "ioperm",
  };

  std::vector<DeniedSyscall> out;
  out.reserve(sizeof(kNames) / sizeof(kNames[0]));
  for (const char* name : kNames) {
    const int nr = ::seccomp_syscall_resolve_name(name);
    if (nr != __NR_SCMP_ERROR) {
      out.push_back({name, nr});
    }
  }
  return out;
}

// Reads libseccomp's BPF export back into memory. seccomp_export_bpf writes to
// an fd, so a pipe is the least awkward way to capture it without a temp file.
Expected<std::string> export_bpf(::scmp_filter_ctx sctx) {
  int fds[2];
  if (::pipe2(fds, O_CLOEXEC) != 0) {
    return Err(Error::syscall(Op::InstallSeccomp, "pipe2", errno,
                              "exporting the seccomp program"));
  }
  Fd read_end(fds[0]);
  Fd write_end(fds[1]);

  // A compiled deny-list profile is a few kilobytes, comfortably inside the
  // 64KB pipe buffer, so exporting fully before reading cannot deadlock. If it
  // ever grew past that, this would need a thread or a temp file - and the
  // size check below is what would catch the growth.
  const int rc = ::seccomp_export_bpf(sctx, write_end.get());
  if (rc != 0) {
    return Err(Error::syscall(Op::InstallSeccomp, "seccomp_export_bpf", -rc,
                              "compiling the seccomp profile"));
  }
  write_end.reset();  // so the read below sees EOF

  std::string blob;
  char buf[4096];
  for (;;) {
    const ssize_t n = ::read(read_end.get(), buf, sizeof(buf));
    if (n == 0) {
      break;
    }
    if (n < 0) {
      if (errno == EINTR) {
        continue;
      }
      return Err(Error::syscall(Op::InstallSeccomp, "read", errno,
                                "reading the exported seccomp program"));
    }
    blob.append(buf, static_cast<std::size_t>(n));
  }
  return blob;
}

}  // namespace
#endif  // MC_ENABLE_SECCOMP

Expected<void> build_seccomp_program(const SecurityConfig& sec,
                                     ChildContext& ctx) {
  if (sec.seccomp == SeccompMode::Off) {
    ctx.install_seccomp = false;
    return Ok();
  }

  // A privileged container keeps CAP_SYS_ADMIN, so a filter would be a fig
  // leaf: the process could install a permissive one of its own. Saying so is
  // better than pretending the filter means something.
  if (sec.privileged) {
    ctx.install_seccomp = false;
    return Ok();
  }

#if !MC_ENABLE_SECCOMP
  (void)ctx;
  return Err(Error::unsupported(
      Op::InstallSeccomp,
      "a seccomp profile was requested but this build has no libseccomp. "
      "Rebuild with -DMC_ENABLE_SECCOMP=ON, or pass --seccomp=off to run "
      "without a filter - which is less safe, and is why it is not the "
      "default"));
#else
  if (sec.seccomp == SeccompMode::Profile) {
    return Err(Error::unsupported(
        Op::InstallSeccomp,
        "loading a seccomp profile from a file is not implemented yet; "
        "--seccomp=default uses the built-in deny list"));
  }

  // Default action ALLOW with explicit denials - the deny-list trade
  // documented above.
  ::scmp_filter_ctx sctx = ::seccomp_init(SCMP_ACT_ALLOW);
  if (sctx == nullptr) {
    return Err(Error::syscall(Op::InstallSeccomp, "seccomp_init", ENOMEM,
                              "allocating the seccomp context"));
  }
  ScopeGuard release([sctx] { ::seccomp_release(sctx); });

  for (const DeniedSyscall& sc : denied_syscalls()) {
    // EPERM rather than SCMP_ACT_KILL: a killed process gives the user a bare
    // SIGSYS with no indication of which syscall died, whereas EPERM surfaces
    // as an ordinary "operation not permitted" the program can report itself.
    const int rc =
        ::seccomp_rule_add(sctx, SCMP_ACT_ERRNO(EPERM), sc.number, 0);
    if (rc != 0) {
      return Err(
          Error::syscall(Op::InstallSeccomp, "seccomp_rule_add", -rc,
                         std::string("adding a deny rule for ") + sc.name));
    }
  }

  const std::string blob = MC_TRY(export_bpf(sctx));

  // A sock_filter is 8 bytes. A blob that is not a whole number of
  // instructions means the export was truncated, and must not be installed.
  constexpr std::size_t kInsnSize = 8;
  if (blob.empty() || blob.size() % kInsnSize != 0) {
    return Err(Error::invalid(
        Op::InstallSeccomp,
        "the exported seccomp program is " + std::to_string(blob.size()) +
            " bytes, which is not a whole number of BPF instructions"));
  }
  const std::size_t insns = blob.size() / kInsnSize;
  if (insns > kMaxSeccompInsns) {
    return Err(Error::invalid(
        Op::InstallSeccomp, "the seccomp program is " + std::to_string(insns) +
                                " instructions, over the " +
                                std::to_string(kMaxSeccompInsns) +
                                " that fit in the child context"));
  }

  std::memcpy(ctx.seccomp_insns, blob.data(), blob.size());
  ctx.seccomp_insn_count = insns;
  ctx.install_seccomp = true;
  return Ok();
#endif
}

// ---------------------------------------------------------------------------
// Child side. No allocation past this point.
// ---------------------------------------------------------------------------

ChildStatus step_set_no_new_privs(const ChildContext& ctx) noexcept {
  if (!ctx.no_new_privs) {
    return ChildStatus::success();
  }
  if (::prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
    return ChildStatus::fail(Op::SetNoNewPrivs, errno);
  }
  return ChildStatus::success();
}

ChildStatus step_install_seccomp(const ChildContext& ctx) noexcept {
  if (!ctx.install_seccomp || ctx.seccomp_insn_count == 0) {
    return ChildStatus::success();
  }

  // sock_fprog only points at the instruction array; nothing is copied, so
  // this allocates nothing. The const_cast is because the kernel's struct
  // predates const-correctness, not because the filter is modified.
  struct ::sock_fprog prog {};
  prog.len = static_cast<unsigned short>(ctx.seccomp_insn_count);
  prog.filter = reinterpret_cast<struct ::sock_filter*>(
      const_cast<unsigned char*>(ctx.seccomp_insns));

  // The raw syscall, not libseccomp's seccomp_load(), which would allocate.
  if (::syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0U, &prog) != 0) {
    return ChildStatus::fail(Op::InstallSeccomp, errno);
  }
  return ChildStatus::success();
}

}  // namespace mc
