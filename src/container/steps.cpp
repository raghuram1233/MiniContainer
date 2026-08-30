// SPDX-License-Identifier: MIT
//
// MiniContainer - the child-side step table and entry point.
//
// EVERYTHING BELOW THE PARENT/CHILD LINE
// --------------------------------------
// container_child_main() is what clone3() lands in. From that moment until
// execve() this process must not allocate, take a lock, or throw - it may be
// holding a malloc lock inherited from a thread that does not exist in this
// address space, and a single malloc() would deadlock it forever with no
// diagnostic. Every function here obeys that: stack buffers, raw syscalls,
// ChildStatus returns.
//
// WHY A TABLE RATHER THAN ONE FUNCTION THAT DOES EVERYTHING
// ---------------------------------------------------------
// Container setup is ~19 ordered operations, any of which can fail, and the
// interesting question when one does is always "which one, and what errno".
// A table of {Op, function} pairs makes that structural: the runner reports
// the Op of whichever entry failed, so the parent can reconstruct an error
// naming the exact step without the child ever formatting a string.
//
// It also puts the ORDER on one screen, which matters because the order is
// load-bearing: mounts before pivot_root, no_new_privs before seccomp,
// capabilities dropped only after every step that needed them.
#include <errno.h>
#include <string.h>
#include <unistd.h>

#include <cstring>

#include "minicontainer/container.h"
#include "minicontainer/errors.h"
#include "minicontainer/filesystem.h"
#include "minicontainer/logging.h"
#include "minicontainer/network.h"
#include "minicontainer/security.h"

namespace mc {

namespace {

// The UTS step lives here rather than in a module of its own: it is a single
// syscall, and inventing a src/namespace/ translation unit to hold one line
// would be structure for its own sake.
ChildStatus step_set_hostname(const ChildContext& ctx) noexcept {
  if (ctx.hostname == nullptr || ctx.hostname[0] == '\0') {
    return ChildStatus::success();
  }
  if (::sethostname(ctx.hostname, std::strlen(ctx.hostname)) != 0) {
    return ChildStatus::fail(Op::SetHostname, errno);
  }
  return ChildStatus::success();
}

// The table. Order is the execution order frozen in errors.h's MC_OP_LIST;
// if you change one, change both.
constexpr ChildStep kSteps[] = {
    {Op::SetHostname, &step_set_hostname, "SetHostname"},
    {Op::MakeRootPrivate, &step_make_root_private, "MakeRootPrivate"},
    {Op::BindRootfs, &step_bind_rootfs, "BindRootfs"},
    {Op::MountProc, &step_mount_proc, "MountProc"},
    {Op::MountSys, &step_mount_sys, "MountSys"},
    {Op::MountDev, &step_mount_dev, "MountDev"},
    {Op::CreateDeviceNode, &step_create_device_nodes, "CreateDeviceNode"},
    {Op::MountDevPts, &step_mount_devpts, "MountDevPts"},
    {Op::MountTmp, &step_mount_tmp, "MountTmp"},
    // Bind mounts come after the pseudo-filesystems so that a user bind can
    // deliberately shadow one, rather than being silently overmounted by it.
    {Op::BindRootfs, &step_bind_mounts, "BindMounts"},
    {Op::ConfigureAddress, &step_configure_address, "ConfigureAddress"},
    {Op::PivotRoot, &step_pivot_root, "PivotRoot"},
    {Op::UmountOldRoot, &step_umount_old_root, "UmountOldRoot"},
    {Op::RemountReadonly, &step_remount_readonly, "RemountReadonly"},
    // The working directory resolves inside the NEW root, so it must follow
    // the pivot: a --workdir that exists only in the container would
    // otherwise be looked up against the host's tree and fail.
    {Op::ChildSetup, &step_set_working_dir, "SetWorkingDir"},
    // Privilege teardown last, in this order: no_new_privs must precede
    // seccomp (the filter is rejected with EACCES otherwise, once
    // CAP_SYS_ADMIN is gone), and capabilities must survive until every mount
    // above has run.
    {Op::SetNoNewPrivs, &step_set_no_new_privs, "SetNoNewPrivs"},
    {Op::DropCapabilities, &step_drop_capabilities, "DropCapabilities"},
    {Op::SwitchUser, &step_switch_user, "SwitchUser"},
    {Op::InstallSeccomp, &step_install_seccomp, "InstallSeccomp"},
};

}  // namespace

const ChildStep* child_step_table(std::size_t& count) noexcept {
  count = sizeof(kSteps) / sizeof(kSteps[0]);
  return kSteps;
}

ChildStatus run_child_steps(const ChildContext& ctx) noexcept {
  std::size_t count = 0;
  const ChildStep* steps = child_step_table(count);
  for (std::size_t i = 0; i < count; ++i) {
    const ChildStatus st = steps[i].fn(ctx);
    if (!st.ok()) {
      MC_CLOG(steps[i].name);
      MC_CLOG_N("child: step failed, errno=", static_cast<long>(st.err));
      return st;
    }
  }
  return ChildStatus::success();
}

void report_child_error(int error_fd, ChildStatus status,
                        const char* detail) noexcept {
  if (error_fd < 0) {
    return;
  }
  // Built on the stack and written in ONE call: ChildErrorWire is 200 bytes,
  // well under PIPE_BUF, so the write is atomic and the parent can never
  // observe a half-formed record.
  ChildErrorWire wire{};
  wire.magic = kChildErrorMagic;
  wire.op = static_cast<std::uint16_t>(status.op);
  wire.err = status.err;
  wire.detail_len = 0;

  if (detail != nullptr) {
    // strlen and memcpy are async-signal-safe; snprintf is not, which is why
    // `detail` is always a plain literal rather than something formatted here.
    std::size_t n = std::strlen(detail);
    if (n > sizeof(wire.detail)) {
      n = sizeof(wire.detail);
    }
    std::memcpy(wire.detail, detail, n);
    wire.detail_len = static_cast<std::uint16_t>(n);
  }

  // A short write cannot be retried meaningfully here: if the parent has gone
  // away there is nobody to tell, so the result is deliberately discarded.
  const ssize_t rc = ::write(error_fd, &wire, sizeof(wire));
  (void)rc;
}

int container_child_main(void* arg) noexcept {
  const ChildContext& ctx = *static_cast<const ChildContext*>(arg);

  // First, so that every MC_CLOG below actually goes somewhere.
  child::set_log_fd(ctx.log_fd);
  MC_CLOG("child: alive, waiting for parent handshake");

  // Block until the parent says the uid/gid maps are written and the veth has
  // been moved in. Until that byte arrives, almost every privileged operation
  // in a new user namespace fails and the network interface does not exist.
  if (ctx.sync_fd >= 0) {
    char go = 0;
    const ssize_t n = ::read(ctx.sync_fd, &go, 1);
    if (n != 1 || go != 'G') {
      // The parent died or aborted the launch. There is nothing to report to,
      // and nothing to clean up: the kernel reclaims the namespaces with us.
      MC_CLOG("child: handshake failed; parent went away");
      ::_exit(127);
    }
  }
  MC_CLOG("child: handshake complete, running setup steps");

  const ChildStatus st = run_child_steps(ctx);
  if (!st.ok()) {
    report_child_error(ctx.error_fd, st, "container setup step failed");
    ::_exit(127);
  }

  MC_CLOG("child: setup complete, forking entrypoint under the init shim");

  // WHY THE ENTRYPOINT IS NOT PID 1 ITSELF
  // --------------------------------------
  // The kernel does not apply DEFAULT signal actions to PID 1. A shell that
  // never installs a SIGTERM handler still dies to SIGTERM as an ordinary
  // process, but as PID 1 it simply ignores it - so `minicontainer stop` would
  // wait out its whole timeout and SIGKILL every container. PID 1 also has to
  // reap orphans, or they accumulate as zombies until pids.max is exhausted.
  //
  // So PID 1 is the init shim, and the entrypoint is its child. This costs one
  // extra process per container and is what every real runtime does.
  const ::pid_t entry = ::fork();
  if (entry < 0) {
    report_child_error(ctx.error_fd, ChildStatus::fail(Op::ChildSetup, errno),
                       "could not fork the entrypoint under the init shim");
    ::_exit(127);
  }

  if (entry == 0) {
    // Redirect in the ENTRYPOINT, not the shim: the shim's own diagnostics
    // are not container output and should not land in the log file. dup2 is
    // async-signal-safe and allocates nothing, so it is safe here.
    if (ctx.stdout_fd >= 0) {
      (void)::dup2(ctx.stdout_fd, STDOUT_FILENO);
    }
    if (ctx.stderr_fd >= 0) {
      (void)::dup2(ctx.stderr_fd, STDERR_FILENO);
    }
    ::execve(ctx.argv[0], ctx.argv, ctx.envp);
    // execve only returns on failure, and this is the most common real-world
    // container failure - the entrypoint is missing from the rootfs, or is
    // dynamically linked against an interpreter that is not there.
    report_child_error(ctx.error_fd, ChildStatus::fail(Op::Execve, errno),
                       "execve failed: is the entrypoint present in the "
                       "rootfs, along with its shared libraries?");
    ::_exit(127);
  }

  // The shim must drop its copy of the error pipe now. The parent detects a
  // successful start by reading EOF on that pipe, and EOF only arrives once
  // EVERY writer has closed: the entrypoint's copy goes on execve (it is
  // O_CLOEXEC), but this one would be held for the container's whole life and
  // the parent would block forever.
  if (ctx.error_fd >= 0) {
    ::close(ctx.error_fd);
  }

  MC_CLOG("child: entrypoint running, entering init shim as PID 1");
  InitShimOptions opts;
  opts.forward_signals = true;
  opts.reap_orphans = true;
  Expected<ExitStatus> status = run_init_shim(entry, opts);
  if (!status) {
    ::_exit(127);
  }

  // Exit with the entrypoint's own status so the parent's wait_for() reports
  // what the container actually did. A signal death becomes 128+n here, the
  // shell convention, which is the closest a shim can get to re-raising it.
  ::_exit(status->to_shell_code());
}

}  // namespace mc
