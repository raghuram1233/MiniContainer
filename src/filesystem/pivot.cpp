// SPDX-License-Identifier: MIT
//
// MiniContainer - pivot_root and the steps that must follow it.
//
// This is the moment the container stops being "a process with some extra
// mounts" and becomes a process that cannot see the host filesystem at all.
// Everything here is CHILD-SIDE: post-clone, pre-execve, no allocation.
//
// WHY THE ORDER IS PIVOT -> UMOUNT -> REMOUNT-RO -> CHDIR
// -------------------------------------------------------
// pivot_root leaves the old root mounted at /.oldroot, still fully reachable -
// the isolation is not real until it is detached. Remounting read-only has to
// come after that detach, because the remount applies to "/" and we want it to
// apply to the container's root, not to a tree that still has the host's root
// hanging off it. And chdir to the user's --workdir must be last of all: it
// resolves inside the NEW root, so doing it earlier would look the path up
// against the host's tree and either fail or, worse, succeed against the wrong
// directory.
//
// The path helper below is a deliberate near-duplicate of the one in
// mount.cpp. It is ~15 lines of no-allocation string handling, and sharing it
// would mean giving two translation units a common internal header for the
// sake of one function. Each child-side TU keeping its own is the smaller
// cost.
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/syscall.h>

#include <errno.h>
#include <unistd.h>

#include <cstddef>
#include <cstring>

#include "minicontainer/container.h"
#include "minicontainer/errors.h"
#include "minicontainer/filesystem.h"

namespace mc {

namespace {

constexpr std::size_t kPathMax = 4096;

// The directory pivot_root moves the old root to. It must live INSIDE the new
// root - a kernel requirement, not a convention - and the leading dot keeps it
// out of a plain `ls` in the brief window before it is removed.
constexpr const char* kOldRootName = ".oldroot";
constexpr const char* kOldRootAbs = "/.oldroot";

// Joins two path fragments into a fixed buffer. Returns false rather than
// truncating: a silently shortened path here would pivot into the wrong
// directory, which is far worse than a clean failure.
bool path_join(char (&buf)[kPathMax], const char* a, const char* b) noexcept {
  const std::size_t la = std::strlen(a);
  const std::size_t lb = std::strlen(b);
  const bool need_sep = la > 0 && a[la - 1] != '/' && b[0] != '/';
  if (la + lb + (need_sep ? 1 : 0) + 1 > kPathMax) {
    return false;
  }
  std::memcpy(buf, a, la);
  std::size_t n = la;
  if (need_sep) {
    buf[n++] = '/';
  }
  std::memcpy(buf + n, b, lb);
  buf[n + lb] = '\0';
  return true;
}

}  // namespace

ChildStatus step_pivot_root(const ChildContext& ctx) noexcept {
  char oldroot[kPathMax];
  if (!path_join(oldroot, ctx.rootfs, kOldRootName)) {
    return ChildStatus::fail(Op::PivotRoot, ENAMETOOLONG);
  }

  // EEXIST is fine: a rootfs reused from a previous run may still have it.
  if (::mkdir(oldroot, 0700) != 0 && errno != EEXIST) {
    return ChildStatus::fail(Op::PivotRoot, errno);
  }

  // glibc has no pivot_root wrapper, so this is a raw syscall. Both arguments
  // must be mount points and neither may be "/" - step_bind_rootfs is what
  // makes the first of those true for an ordinary directory.
  if (::syscall(SYS_pivot_root, ctx.rootfs, oldroot) != 0) {
    return ChildStatus::fail(Op::PivotRoot, errno);
  }

  // After the pivot our cwd is still an fd into the OLD root. Leaving it there
  // would keep that tree alive and give anything walking ".." a path out, so
  // move into the new root immediately.
  if (::chdir("/") != 0) {
    return ChildStatus::fail(Op::PivotRoot, errno);
  }
  return ChildStatus::success();
}

ChildStatus step_umount_old_root(const ChildContext&) noexcept {
  // MNT_DETACH (a lazy unmount) rather than a plain umount2: a plain unmount
  // fails EBUSY if anything still references the old root - an inherited fd, a
  // library the dynamic linker mapped, a cwd not yet changed. The lazy form
  // disconnects the mount from this namespace's tree immediately, so no new
  // access can reach it, and defers teardown until the last reference drops.
  // Setup must not have to race every fd that might still be open.
  if (::umount2(kOldRootAbs, MNT_DETACH) != 0) {
    return ChildStatus::fail(Op::UmountOldRoot, errno);
  }

  // Now empty, so removing it is tidiness - but leaving it would advertise to
  // anything inside the container that a pivot happened here.
  if (::rmdir(kOldRootAbs) != 0 && errno != ENOENT) {
    return ChildStatus::fail(Op::UmountOldRoot, errno);
  }
  return ChildStatus::success();
}

ChildStatus step_remount_readonly(const ChildContext& ctx) noexcept {
  if (!ctx.readonly_rootfs) {
    return ChildStatus::success();
  }
  // MS_BIND is required alongside MS_REMOUNT here: without it the kernel
  // reinterprets the call as a remount of the underlying superblock, which
  // would make the filesystem read-only for the HOST too whenever the rootfs
  // is a bind of a host directory.
  if (::mount(nullptr, "/", nullptr, MS_REMOUNT | MS_BIND | MS_RDONLY,
              nullptr) != 0) {
    return ChildStatus::fail(Op::RemountReadonly, errno);
  }
  return ChildStatus::success();
}

ChildStatus step_set_working_dir(const ChildContext& ctx) noexcept {
  if (ctx.working_dir == nullptr || ctx.working_dir[0] == '\0') {
    return ChildStatus::success();
  }
  // Deliberately no fallback to "/": a --workdir that does not exist in the
  // image is a real configuration error, and silently starting the entrypoint
  // somewhere else would produce a container that looks fine and behaves
  // wrongly.
  if (::chdir(ctx.working_dir) != 0) {
    return ChildStatus::fail(Op::ChildSetup, errno);
  }
  return ChildStatus::success();
}

}  // namespace mc
