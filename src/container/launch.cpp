// SPDX-License-Identifier: MIT
//
// MiniContainer - parent-side container launch.
//
// This is where every module meets. The sequence below is the whole reason
// process.h documents a three-pipe handshake: several things MUST happen after
// the child exists but before it is allowed to run, and the only way to
// express "exists but not running yet" is to make the child block on a pipe.
//
//   clone3()                     child is created, immediately blocks on sync
//   write setgroups/uid_map      only the parent may write these, and only
//   write gid_map                once the child's /proc entry exists
//   create veth, move peer in    the netns does not exist until clone returns
//   send 'G'                     child wakes and runs the step table
//   read error pipe              EOF = execve succeeded; data = it failed
//
// WHY THE ERROR PIPE IS READ AFTER THE HANDSHAKE, NOT POLLED
// ----------------------------------------------------------
// The error pipe's write end is O_CLOEXEC in the child, so execve() closes it
// and the parent's read() returns 0. That gives an unambiguous signal with no
// timeout and no polling: EOF means "the child got all the way to running the
// entrypoint", a full ChildErrorWire means "it failed, here is the step and
// the errno", and anything else means it died in a way worth reporting as
// such.
//
// EVERY FAILURE PATH UNWINDS
// --------------------------
// A half-created container - a cgroup with no process, a veth dangling off the
// bridge - is worse than no container, because nothing will ever clean it up.
// Rollback holds an undo action per resource as it is created, and is
// dismissed only once the launch has fully succeeded.
#include <sys/wait.h>

#include <fcntl.h>
#include <signal.h>
#include <unistd.h>

#include <cerrno>
#include <memory>
#include <string>
#include <vector>

#include "minicontainer/cgroup.h"
#include "minicontainer/container.h"
#include "minicontainer/errors.h"
#include "minicontainer/filesystem.h"
#include "minicontainer/logging.h"
#include "minicontainer/network.h"
#include "minicontainer/process.h"
#include "minicontainer/syscall.h"

// glibc's <sched.h> on Ubuntu 24.04 does not expose CLONE_INTO_CGROUP even
// though the kernel has had it since 5.7, and <linux/sched.h> collides with
// the glibc header. src/process/clone.cpp defines it the same way for the same
// reason; if you change one, change both.
#ifndef CLONE_INTO_CGROUP
#define CLONE_INTO_CGROUP 0x200000000ULL
#endif

namespace mc {

namespace {

// The uid_map/gid_map handshake. Only the parent can write these files, and
// only once the child exists; until they are written the child's uid is the
// overflow uid and almost every privileged operation fails.
Expected<void> write_id_maps(::pid_t pid, const SecurityConfig& sec) {
  const std::string base = "/proc/" + std::to_string(pid) + "/";

  // setgroups MUST be denied before gid_map is written, or the kernel refuses
  // the gid_map write outright. Keeping setgroups available inside a new user
  // namespace would let an unprivileged user DROP supplementary groups and so
  // gain access to files protected by a negative group permission.
  MC_CHECK(write_file(base + "setgroups", "deny", Op::DenySetgroups));

  const std::string uid_map = "0 " + std::to_string(sec.userns_host_uid) + " " +
                              std::to_string(sec.userns_size) + "\n";
  MC_CHECK(write_file(base + "uid_map", uid_map, Op::WriteUidMap));

  const std::string gid_map = "0 " + std::to_string(sec.userns_host_gid) + " " +
                              std::to_string(sec.userns_size) + "\n";
  MC_CHECK(write_file(base + "gid_map", gid_map, Op::WriteGidMap));

  return Ok();
}

// Turns whatever arrived on the error pipe into a parent-side Error. A short
// read is itself information - the child died between starting and finishing
// the record - and is not something to paper over.
Expected<void> read_child_error(Pipe& err_pipe, ::pid_t pid) {
  ChildErrorWire wire{};
  const ssize_t n = ::read(err_pipe.read_end.get(), &wire, sizeof(wire));

  if (n == 0) {
    return Ok();  // EOF: CLOEXEC closed it, so execve() succeeded.
  }
  if (n < 0) {
    return Err(Error::syscall(Op::SyncHandshake, "read", errno,
                              "reading the child error pipe"));
  }
  if (n != static_cast<ssize_t>(sizeof(wire)) ||
      wire.magic != kChildErrorMagic) {
    return Err(Error::invalid(
        Op::SyncHandshake,
        "the container process reported a malformed error record (" +
            std::to_string(n) + " bytes); it probably died mid-setup"));
  }

  // The child failed a step. Reap it now so it does not linger as a zombie
  // while we report, since the caller will never wait on it.
  int status = 0;
  (void)::waitpid(pid, &status, 0);

  return Err(Error::from_child(wire));
}

bool needs_cgroup(const Resources& r) noexcept {
  return r.memory_bytes.has_value() || r.memory_swap_bytes.has_value() ||
         r.cpus.has_value() || r.cpu_shares.has_value() ||
         r.pids_max.has_value() || r.cpuset_cpus.has_value();
}

}  // namespace

Expected<LaunchResult> launch_container(const ContainerConfig& config,
                                        const RuntimePaths& paths) {
  // --- preflight: everything cheap and non-destructive, first ---
  MC_CHECK(validate_rootfs(config.rootfs_path, config.args.empty()
                                                   ? std::string()
                                                   : config.args[0]));

  // ChildContext is ~64KB. Heap-allocate rather than stack: the child reads it
  // after clone, so it must stay valid for the whole launch.
  auto ctx = std::make_unique<ChildContext>();
  MC_CHECK(build_child_context(config, *ctx));

  Rollback rollback;
  LaunchResult result;

  // --- cgroup, created before the child so CLONE_INTO_CGROUP can use it ---
  CgroupManager cgroup;
  Fd cgroup_fd;
  const bool want_cgroup = needs_cgroup(config.resources);

  if (want_cgroup) {
    cgroup = MC_TRY(CgroupManager::create(paths, config.id, config.resources));
    result.cgroup_path = cgroup.path();
    rollback.push("cgroup " + cgroup.path(), [paths, id = config.id]() {
      auto cg = CgroupManager::open(paths, id);
      if (cg) {
        (void)cg->remove();
      }
    });
    MC_CHECK(cgroup.apply_limits(config.resources));

    if (clone3_into_cgroup_supported()) {
      cgroup_fd = MC_TRY(cgroup.open_dir_fd());
    } else {
      MC_LOG_WARN(
          "this kernel has no CLONE_INTO_CGROUP; the container will run "
          "briefly outside its cgroup before being attached");
    }
  }

  // --- networking: allocate the address now, create the veth after clone ---
  NetworkAllocation alloc;
  if (config.network.mode == NetworkMode::Bridge) {
    if (!ip_forwarding_enabled()) {
      MC_LOG_WARN(
          "net.ipv4.ip_forward is 0; the container will have an address but no "
          "route off the bridge. Fix with: sysctl -w net.ipv4.ip_forward=1");
    }
    MC_CHECK(ensure_bridge(config.network));

    alloc.bridge = config.network.bridge_name;
    alloc.gateway = config.network.gateway_ip;
    // The host-side name is derived from the container id and truncated to
    // IFNAMSIZ-1 (15); the kernel rejects anything longer outright.
    alloc.veth_host = ("mc-" + config.id).substr(0, 15);
    alloc.veth_container = "eth0";
    alloc.published = config.network.ports;
    alloc.ip_cidr = config.network.container_ip.has_value()
                        ? *config.network.container_ip
                        : MC_TRY(allocate_ip(config.network, {}));

    // The child needs these as arena strings, not std::string.
    ctx->container_ip_cidr = arena_put(*ctx, alloc.ip_cidr.c_str());
    ctx->gateway_ip = arena_put(*ctx, alloc.gateway.c_str());
    ctx->veth_name = arena_put(*ctx, alloc.veth_container.c_str());
    if (ctx->container_ip_cidr == nullptr || ctx->gateway_ip == nullptr ||
        ctx->veth_name == nullptr) {
      return Err(Error::invalid(
          Op::ValidateConfig,
          "ran out of string space storing the network configuration"));
    }
  }

  // --- the pipes ---
  Pipe sync_pipe = MC_TRY(Pipe::create());
  Pipe err_pipe = MC_TRY(Pipe::create());

  ctx->sync_fd = sync_pipe.read_end.get();
  ctx->error_fd = err_pipe.write_end.get();
  ctx->log_fd = -1;  // the child logs only when explicitly enabled

  // A detached container has no terminal to write to, so its output is
  // captured to <state>/<id>/logs/output.log for `minicontainer logs`. An
  // attached run deliberately inherits the caller's stdout/stderr instead:
  // the user is watching, and buffering their output into a file they would
  // then have to go and read would be worse, not better.
  Fd log_file;
  if (config.detach) {
    const std::string dir = paths.log_dir(config.id);
    MC_CHECK(make_directories(dir));
    const std::string path = dir + "/output.log";
    log_file.reset(
        ::open(path.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644));
    if (!log_file.valid()) {
      return Err(Error::syscall(Op::OpenFile, "open", errno,
                                "creating the container log file " + path));
    }
    // O_CLOEXEC is right for our copy but wrong for the child's: the child
    // dup2()s these onto fd 1 and 2, and dup2 clears CLOEXEC on the new
    // descriptors, so the redirect survives execve while this original does
    // not leak into the container.
    ctx->stdout_fd = log_file.get();
    ctx->stderr_fd = log_file.get();
  }

  // --- clone ---
  CloneRequest req;
  req.flags = clone_flags_for(config);
  req.exit_signal = SIGCHLD;
  if (cgroup_fd.valid()) {
    req.flags |= CLONE_INTO_CGROUP;
    req.cgroup_fd = cgroup_fd.get();
  }

  CloneResult cloned =
      MC_TRY(clone_process(req, &container_child_main, ctx.get()));
  result.pid = cloned.pid;
  result.pidfd = std::move(cloned.pidfd);

  // From here on any failure must also kill the child: it is blocked on the
  // sync pipe and would otherwise wait forever.
  const ::pid_t child_pid = result.pid;
  rollback.push("container process " + std::to_string(child_pid), [child_pid] {
    ::kill(child_pid, SIGKILL);
    int st = 0;
    (void)::waitpid(child_pid, &st, 0);
  });

  // The child owns these ends now. Closing our copies is what makes the EOF
  // signal work: holding the error pipe's write end open would make the read
  // below block forever even after a successful execve.
  ctx->sync_fd = -1;
  ctx->error_fd = -1;
  sync_pipe.read_end.reset();
  err_pipe.write_end.reset();

  // --- everything that must happen while the child is still blocked ---
  if (config.security.userns) {
    MC_CHECK(write_id_maps(result.pid, config.security));
  }

  if (config.network.mode == NetworkMode::Bridge) {
    MC_CHECK(create_veth_pair(alloc, result.pid));
    const NetworkAllocation alloc_copy = alloc;
    rollback.push("veth " + alloc.veth_host,
                  [alloc_copy] { (void)teardown_network(alloc_copy); });
    MC_CHECK(attach_to_bridge(alloc));
    if (config.network.enable_nat) {
      MC_CHECK(configure_nat(config.network));
      alloc.nat_configured = true;
    }
    if (!alloc.published.empty()) {
      const std::vector<std::string> netsh =
          MC_TRY(configure_port_mappings(alloc));
      for (const std::string& cmd : netsh) {
        MC_LOG_INFO(
            "to reach this port from Windows, run in an elevated PowerShell: "
            << cmd);
      }
    }
  }

  if (want_cgroup && !cgroup_fd.valid()) {
    MC_CHECK(cgroup.attach(result.pid));
  }

  // --- release the child ---
  MC_CHECK(sync_pipe.write_byte('G'));
  sync_pipe.write_end.reset();

  // --- did it reach execve? ---
  MC_CHECK(read_child_error(err_pipe, result.pid));

  result.veth_host = alloc.veth_host;
  rollback.dismiss();
  MC_LOG_DEBUG("container " << config.id << " started as pid " << result.pid);
  return result;
}

}  // namespace mc
