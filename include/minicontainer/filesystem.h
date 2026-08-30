// SPDX-License-Identifier: MIT
//
// MiniContainer - Tier 2: filesystem isolation.
//
// EVERY step_* FUNCTION HERE IS CHILD-SIDE. They run post-clone, pre-execve,
// inside the new mount namespace, and are bound by container.h's
// no-allocation rule: ChildStatus in, ChildStatus out, no std::string.
//
// WHY pivot_root AND NOT chroot
// -----------------------------
// chroot() only moves the process's root *pointer*; the old root stays mounted
// and reachable. A process holding an fd to a directory outside the new root
// can chroot() a second time and walk out - the classic double-chroot escape.
// pivot_root() moves the mount itself, and after umount2(MNT_DETACH) the old
// root is not merely hidden but gone from this namespace's mount tree.
//
// ORDERING
// --------
// Mounts happen BEFORE pivot_root, against <rootfs>/<dir>, per the execution
// order frozen in errors.h's MC_OP_LIST. Mounting /proc after pivoting would
// require a /proc to already exist in order to resolve the mount, which is the
// wrong way round.
#pragma once

#include <string>

#include "minicontainer/container.h"
#include "minicontainer/errors.h"

namespace mc {

// Make this namespace's mounts private, so nothing we do propagates back to
// the host. Without it a bind mount here can appear on the host's tree, since
// mount propagation defaults to shared on most systems.
ChildStatus step_make_root_private(const ChildContext& ctx) noexcept;

// Bind <rootfs> onto itself. pivot_root requires new_root to be a mount point;
// a plain directory is not one, and the call fails with EINVAL.
ChildStatus step_bind_rootfs(const ChildContext& ctx) noexcept;

// The user's --volume entries: MS_BIND, then a second MS_REMOUNT|MS_RDONLY
// call when read-only. Bind and read-only cannot be set in one mount() call.
ChildStatus step_bind_mounts(const ChildContext& ctx) noexcept;

ChildStatus step_mount_proc(const ChildContext& ctx) noexcept;
ChildStatus step_mount_sys(const ChildContext& ctx) noexcept;
ChildStatus step_mount_dev(const ChildContext& ctx) noexcept;  // tmpfs
ChildStatus step_create_device_nodes(const ChildContext& ctx) noexcept;
ChildStatus step_mount_devpts(const ChildContext& ctx) noexcept;
ChildStatus step_mount_tmp(const ChildContext& ctx) noexcept;

// pivot_root(new_root, put_old) then chdir("/"). put_old must live inside the
// new root; this creates and uses <rootfs>/.oldroot.
ChildStatus step_pivot_root(const ChildContext& ctx) noexcept;

// umount2("/.oldroot", MNT_DETACH) then rmdir it. Lazy, because a plain
// unmount races every fd that might still reference the old root and fails
// EBUSY - see docs/filesystem.md.
ChildStatus step_umount_old_root(const ChildContext& ctx) noexcept;

// Remount / read-only. The last filesystem step, after everything that needed
// to write during setup has already run.
ChildStatus step_remount_readonly(const ChildContext& ctx) noexcept;

// chdir into ContainerConfig::working_dir. Fails rather than falling back to
// "/": a working directory that does not exist is a real configuration error,
// and silently starting somewhere else would be worse than refusing.
ChildStatus step_set_working_dir(const ChildContext& ctx) noexcept;

// ---------------------------------------------------------------------------
// Parent side. Ordinary code; allocates freely.
// ---------------------------------------------------------------------------

// Checks the rootfs exists, is a directory, is not "/", is not under a Windows
// drive mount, and contains the entrypoint binary. Filesystem-touching, so it
// lives here rather than in ContainerConfig::validate(), which is pure by
// contract.
Expected<void> validate_rootfs(const std::string& rootfs_path,
                               const std::string& entrypoint);

// True when `path` is on drvfs/9p, where mknod cannot work at all. Used to
// turn an inscrutable mknod EPERM into an actionable error.
bool is_windows_drive_mount(const std::string& path) noexcept;

}  // namespace mc
