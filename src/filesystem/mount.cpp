// SPDX-License-Identifier: MIT
//
// MiniContainer - filesystem isolation: the mount steps.
//
// Every function here runs between clone() and execve(), so it obeys
// container.h's no-allocation rule to the letter: no std::string, no
// std::vector, no stdio, nothing that can take the malloc lock a vanished
// thread might still hold. Paths are assembled into 4KB stack buffers by
// path_join() below and every failure is a POD ChildStatus.
//
// WHY THE TARGETS ARE <rootfs>/proc AND NOT /proc
// -----------------------------------------------
// The whole mount sequence runs BEFORE pivot_root, against the not-yet-root
// directory, which is the order errors.h's MC_OP_LIST freezes. Mounting after
// the pivot would mean needing a working /proc in order to mount /proc, and
// would leave a window in which the container's root is live but unpopulated.
//
// THE TRAPS THIS FILE EXISTS TO AVOID
// -----------------------------------
//  * Mount propagation defaults to *shared* on any systemd host, so without
//    step_make_root_private every mount below would appear in the host's
//    mount table too - silently, with no error to notice.
//  * pivot_root refuses a new_root that is not itself a mount point, hence
//    step_bind_rootfs binding the rootfs onto itself.
//  * The /dev tmpfs must NOT carry MS_NODEV. MS_NODEV makes device nodes
//    non-functional, which would make the nodes step_create_device_nodes
//    then carefully mknod()s useless.
//  * mknod()'s mode argument is masked by the inherited umask; a perfectly
//    ordinary 022 umask turns /dev/null's 0666 into 0644 and every
//    unprivileged process in the container then fails to write to it. The
//    fix is an explicit chmod(), which is not masked.
//  * MS_BIND and MS_RDONLY cannot be combined in one mount(2) call. A
//    read-only bind is always two calls: bind, then remount.
//  * A rootfs image may or may not ship /proc, /sys, /dev, /tmp. Every
//    target is created first, treating EEXIST as success, because a missing
//    mount point is not a reason to refuse to start.

#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <sys/types.h>

#include <fcntl.h>
#include <unistd.h>

#include <cerrno>
#include <cstddef>

#include "minicontainer/container.h"
#include "minicontainer/errors.h"
#include "minicontainer/filesystem.h"

namespace mc {

namespace {

// The longest path this file will ever build. Spelled out rather than pulled
// from <climits> so that the size of every stack frame here is obvious at a
// glance - these frames live on the child's clone stack.
constexpr std::size_t kPathMax = 4096;

// The bounded strcpy/strcat this module uses in place of std::string.
//
// Overflow is a failure, never a truncation: a truncated path names a
// DIFFERENT directory, and mounting a fresh tmpfs over the wrong directory is
// far worse than refusing to start the container.
bool path_append(char (&buf)[kPathMax], std::size_t& len,
                 const char* text) noexcept {
  if (text == nullptr) {
    return false;
  }
  for (std::size_t i = 0; text[i] != '\0'; ++i) {
    if (len + 1 >= kPathMax) {
      return false;
    }
    buf[len++] = text[i];
  }
  buf[len] = '\0';
  return true;
}

// "<a><b>", e.g. ("/var/lib/mc/rootfs", "/proc"). `b` carries its own leading
// slash so no separator logic is needed and no path can gain a double slash.
bool path_join(char (&buf)[kPathMax], const char* a, const char* b) noexcept {
  std::size_t len = 0;
  buf[0] = '\0';
  return path_append(buf, len, a) && path_append(buf, len, b);
}

bool path_join3(char (&buf)[kPathMax], const char* a, const char* b,
                const char* c) noexcept {
  std::size_t len = 0;
  buf[0] = '\0';
  return path_append(buf, len, a) && path_append(buf, len, b) &&
         path_append(buf, len, c);
}

// mkdir that accepts "it was already there". Whether a rootfs image ships
// /proc is a property of how it was built, not something to fail on.
bool ensure_dir(const char* path, ::mode_t mode) noexcept {
  if (::mkdir(path, mode) == 0) {
    return true;
  }
  return errno == EEXIST;
}

// mkdir -p over every component of `path` except the last. Done in place by
// temporarily terminating the buffer at each '/', which is why `path` is
// mutable and why this needs no second buffer.
bool ensure_parent_dirs(char* path, ::mode_t mode) noexcept {
  for (std::size_t i = 1; path[i] != '\0'; ++i) {
    if (path[i] != '/') {
      continue;
    }
    path[i] = '\0';
    const bool ok = ensure_dir(path, mode);
    path[i] = '/';
    if (!ok) {
      return false;
    }
  }
  return true;
}

bool ensure_dir_recursive(char* path, ::mode_t mode) noexcept {
  return ensure_parent_dirs(path, mode) && ensure_dir(path, mode);
}

// A bind mount's target must match the source's kind: binding a regular file
// onto a directory fails with ENOTDIR. This creates the empty file a
// file-source bind needs, along with any missing parent directories.
bool ensure_file(char* path) noexcept {
  if (!ensure_parent_dirs(path, 0755)) {
    return false;
  }
  const int fd = ::open(path, O_WRONLY | O_CREAT | O_CLOEXEC, 0644);
  if (fd < 0) {
    return false;
  }
  ::close(fd);
  return true;
}

// The shape every pseudo-filesystem step shares: build <rootfs>/<dir>, create
// it if the image did not ship it, then mount.
ChildStatus mount_pseudo(const ChildContext& ctx, Op op, const char* dir,
                         const char* source, const char* fstype,
                         unsigned long flags, const char* options) noexcept {
  if (ctx.rootfs == nullptr) {
    return ChildStatus::fail(op, EINVAL);
  }
  char target[kPathMax];
  if (!path_join(target, ctx.rootfs, dir)) {
    return ChildStatus::fail(op, ENAMETOOLONG);
  }
  if (!ensure_dir_recursive(target, 0755)) {
    return ChildStatus::fail(op, errno);
  }
  MC_CHILD_SYS(op, ::mount(source, target, fstype, flags, options));
  return ChildStatus::success();
}

// The classic minimal /dev. Anything beyond this set is a host device the
// container has no business reaching, which is exactly why /dev is a fresh
// tmpfs populated node by node instead of a bind of the host's /dev.
//
// Namespace-scope and constexpr rather than a function-local static: a
// function-local static with a non-constant initialiser would emit a
// thread-safe-init guard, and taking a guard is precisely what child-side
// code must never do.
constexpr DeviceNodeSpec kDefaultDeviceNodes[] = {
    {"null", 1, 3, 0666},   {"zero", 1, 5, 0666},    {"full", 1, 7, 0666},
    {"random", 1, 8, 0666}, {"urandom", 1, 9, 0666}, {"tty", 5, 0, 0620},
};

}  // namespace

const DeviceNodeSpec* default_device_nodes(std::size_t& count) noexcept {
  count = sizeof(kDefaultDeviceNodes) / sizeof(kDefaultDeviceNodes[0]);
  return kDefaultDeviceNodes;
}

// ---------------------------------------------------------------------------
// Propagation
// ---------------------------------------------------------------------------

ChildStatus step_make_root_private(const ChildContext&) noexcept {
  // MS_REC is load-bearing: without it only the top-level "/" entry turns
  // private and any nested shared mount underneath keeps propagating to the
  // host. This must be the first mount operation the child performs.
  MC_CHILD_SYS(Op::MakeRootPrivate,
               ::mount(nullptr, "/", nullptr, MS_REC | MS_PRIVATE, nullptr));
  return ChildStatus::success();
}

ChildStatus step_bind_rootfs(const ChildContext& ctx) noexcept {
  if (ctx.rootfs == nullptr) {
    return ChildStatus::fail(Op::BindRootfs, EINVAL);
  }
  // Binding the rootfs onto itself is what turns a plain directory into a
  // mount point. pivot_root(2) rejects anything else with EINVAL, and that
  // EINVAL is otherwise one of the least self-explanatory errors in the
  // whole setup sequence. MS_REC carries any mounts already nested inside
  // the image (a pre-populated /dev, say) across with it.
  MC_CHILD_SYS(Op::BindRootfs, ::mount(ctx.rootfs, ctx.rootfs, nullptr,
                                       MS_BIND | MS_REC, nullptr));
  return ChildStatus::success();
}

// ---------------------------------------------------------------------------
// User volumes
// ---------------------------------------------------------------------------

ChildStatus step_bind_mounts(const ChildContext& ctx) noexcept {
  // errors.h is frozen and has no enumerator for a user volume, so these
  // report as BindRootfs - the op that names the syscall actually being
  // made. The detail string the parent attaches carries the source path.
  constexpr Op kOp = Op::BindRootfs;

  if (ctx.bind_count == 0) {
    return ChildStatus::success();
  }
  if (ctx.rootfs == nullptr) {
    return ChildStatus::fail(kOp, EINVAL);
  }

  for (std::size_t i = 0; i < ctx.bind_count; ++i) {
    const BindMountSpec& spec = ctx.binds[i];
    if (spec.source == nullptr || spec.target == nullptr) {
      return ChildStatus::fail(kOp, EINVAL);
    }

    // The target is absolute inside the container, but the pivot has not
    // happened yet, so it has to be resolved against the rootfs.
    char target[kPathMax];
    if (!path_join(target, ctx.rootfs, spec.target)) {
      return ChildStatus::fail(kOp, ENAMETOOLONG);
    }

    struct ::stat st {};
    if (::stat(spec.source, &st) < 0) {
      return ChildStatus::fail(kOp, errno);
    }
    const bool ok = S_ISDIR(st.st_mode) ? ensure_dir_recursive(target, 0755)
                                        : ensure_file(target);
    if (!ok) {
      return ChildStatus::fail(kOp, errno);
    }

    MC_CHILD_SYS(
        kOp, ::mount(spec.source, target, nullptr, MS_BIND | MS_REC, nullptr));

    if (spec.read_only) {
      // MS_BIND|MS_RDONLY in a single call is silently ignored by the
      // kernel - the mount appears, writable, and nothing reports an error.
      // A read-only bind is always two calls.
      MC_CHILD_SYS(kOp, ::mount(nullptr, target, nullptr,
                                MS_REMOUNT | MS_BIND | MS_RDONLY, nullptr));
    }
  }
  return ChildStatus::success();
}

// ---------------------------------------------------------------------------
// Pseudo-filesystems
// ---------------------------------------------------------------------------

ChildStatus step_mount_proc(const ChildContext& ctx) noexcept {
  // A fresh procfs, not a bind of the host's: procfs is scoped to the
  // mounting process's PID namespace, so mounting it here is what makes
  // `ps` inside the container show only the container's own processes.
  // NOEXEC/NOSUID/NODEV because nothing under /proc is ever a legitimate
  // thing to execute or to trust a setuid bit from.
  return mount_pseudo(ctx, Op::MountProc, "/proc", "proc", "proc",
                      MS_NOSUID | MS_NODEV | MS_NOEXEC, nullptr);
}

ChildStatus step_mount_sys(const ChildContext& ctx) noexcept {
  if (!ctx.mount_sys) {
    return ChildStatus::success();
  }
  // Read-only on top of the usual three: /sys exposes host hardware and
  // kernel tunables, and a container that can write there can reconfigure
  // the machine it is running on.
  return mount_pseudo(ctx, Op::MountSys, "/sys", "sysfs", "sysfs",
                      MS_NOSUID | MS_NODEV | MS_NOEXEC | MS_RDONLY, nullptr);
}

ChildStatus step_mount_dev(const ChildContext& ctx) noexcept {
  // Note the absence of MS_NODEV: this is the one mount in the whole
  // sequence that must permit device nodes, since the next step creates
  // them here. MS_STRICTATIME matches what runc uses and keeps a tmpfs
  // from inheriting surprising relatime behaviour.
  return mount_pseudo(ctx, Op::MountDev, "/dev", "tmpfs", "tmpfs",
                      MS_NOSUID | MS_STRICTATIME, "mode=755,size=64k");
}

ChildStatus step_create_device_nodes(const ChildContext& ctx) noexcept {
  if (ctx.rootfs == nullptr) {
    return ChildStatus::fail(Op::CreateDeviceNode, EINVAL);
  }

  std::size_t count = 0;
  const DeviceNodeSpec* nodes = default_device_nodes(count);

  for (std::size_t i = 0; i < count; ++i) {
    char path[kPathMax];
    if (!path_join3(path, ctx.rootfs, "/dev/", nodes[i].name)) {
      return ChildStatus::fail(Op::CreateDeviceNode, ENAMETOOLONG);
    }

    const ::mode_t mode = static_cast<::mode_t>(nodes[i].mode);
    const ::dev_t rdev = ::makedev(nodes[i].major, nodes[i].minor);

    // EEXIST keeps this idempotent even against a rootfs that already
    // carried a /dev node through the recursive rootfs bind.
    if (::mknod(path, S_IFCHR | mode, rdev) < 0 && errno != EEXIST) {
      return ChildStatus::fail(Op::CreateDeviceNode, errno);
    }
    // mknod() masks its mode with the umask we inherited from whoever ran
    // the runtime. chmod() does not, so the permissions above are the
    // permissions that actually land.
    MC_CHILD_SYS(Op::CreateDeviceNode, ::chmod(path, mode));
  }
  return ChildStatus::success();
}

ChildStatus step_mount_devpts(const ChildContext& ctx) noexcept {
  if (!ctx.mount_devpts) {
    return ChildStatus::success();
  }
  // newinstance gives the container a private pty index space, so a pty
  // allocated inside cannot collide with, or be reached from, the host's.
  // ptmxmode=0666 makes the instance's own ptmx usable by unprivileged
  // processes in the container.
  //
  // gid=5 (the host's "tty" group) is deliberately NOT passed: inside a user
  // namespace gid 5 may not be mapped at all, and devpts then rejects the
  // mount outright. mode=620 without a gid leaves the pts nodes owned by the
  // creating user, which is what a container without a host tty group wants.
  return mount_pseudo(ctx, Op::MountDevPts, "/dev/pts", "devpts", "devpts",
                      MS_NOSUID | MS_NOEXEC,
                      "newinstance,ptmxmode=0666,mode=620");
}

ChildStatus step_mount_tmp(const ChildContext& ctx) noexcept {
  // Its own tmpfs so that /tmp is isolated from the host's and is emptied
  // when the container's mount namespace dies. mode=1777 is set explicitly
  // because the mkdir that created the mount point was umask-masked.
  return mount_pseudo(ctx, Op::MountTmp, "/tmp", "tmpfs", "tmpfs",
                      MS_NOSUID | MS_NODEV, "mode=1777");
}

}  // namespace mc
