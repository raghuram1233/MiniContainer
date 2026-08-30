// SPDX-License-Identifier: MIT
//
// MiniContainer - parent-side rootfs validation.
//
// PARENT-SIDE, so this allocates freely - unlike everything else in this
// module. It exists because ContainerConfig::validate() is pure by contract:
// it can check that a path is well-formed, but not that it exists, and the
// difference between those two is most of what actually goes wrong.
//
// WHY VALIDATE AT ALL WHEN THE CHILD WOULD FAIL ANYWAY
// ----------------------------------------------------
// It would, but from inside a container that has already been created, after
// namespaces and a cgroup and possibly a veth have been set up and must now be
// torn down - and the error would arrive as a bare errno from a step whose
// context the user cannot see. Checking here turns "container setup step
// PivotRoot failed: ENOTDIR" into "rootfs /tmp/foo is not a directory", before
// anything has been created.
//
// THE drvfs TRAP
// --------------
// On WSL, /mnt/c is drvfs (9p). It cannot represent device nodes at all, so
// mknod fails outright - and it fails with EPERM, which reads exactly like a
// permissions problem and sends people hunting for the wrong thing. Detecting
// it here lets us say what is actually wrong.
#include <sys/stat.h>
#include <sys/statfs.h>

#include <cctype>
#include <cstddef>
#include <string>

#include "minicontainer/errors.h"
#include "minicontainer/filesystem.h"
#include "minicontainer/syscall.h"

namespace mc {

namespace {

// Values from <linux/magic.h>, spelled out rather than included because that
// header drags in a great deal for two constants.
constexpr unsigned long kV9fsMagic = 0x01021997UL;  // 9p, which drvfs is
constexpr unsigned long kFuseMagic = 0x65735546UL;  // some drvfs setups

}  // namespace

bool is_windows_drive_mount(const std::string& path) noexcept {
  // Path-shape check first: it is cheap, and it still works when the path does
  // not exist yet, where statfs would fail for an unrelated reason.
  if (path.rfind("/mnt/", 0) == 0) {
    // "/mnt/c" or "/mnt/c/..." but not "/mnt/data": a single-letter component
    // is what makes it a Windows drive rather than an ordinary mount point.
    constexpr std::size_t after = 5;
    if (path.size() > after &&
        std::isalpha(static_cast<unsigned char>(path[after])) != 0 &&
        (path.size() == after + 1 || path[after + 1] == '/')) {
      return true;
    }
  }

  struct ::statfs sfs {};
  if (::statfs(path.c_str(), &sfs) != 0) {
    return false;  // Cannot tell; the caller's other checks will catch it.
  }
  const auto type = static_cast<unsigned long>(sfs.f_type);
  return type == kV9fsMagic || type == kFuseMagic;
}

Expected<void> validate_rootfs(const std::string& rootfs_path,
                               const std::string& entrypoint) {
  if (rootfs_path.empty()) {
    return Err(Error::invalid(Op::ValidateRootfs,
                              "no rootfs was given; pass --rootfs PATH"));
  }

  // Canonicalise before every other check. It resolves symlinks, so a rootfs
  // that is a symlink to "/" is caught by the check below rather than sneaking
  // past it, and it is the path the child will actually bind-mount.
  const std::string real =
      MC_TRY(canonicalize(rootfs_path, Op::ValidateRootfs));

  if (real == "/") {
    return Err(Error::invalid(
        Op::ValidateRootfs,
        "refusing to use / as a container rootfs: the container would "
        "bind-mount and pivot into the host's own root filesystem"));
  }

  if (!is_directory(real)) {
    return Err(Error::invalid(Op::ValidateRootfs,
                              "rootfs " + real + " is not a directory"));
  }

  if (is_windows_drive_mount(real)) {
    return Err(Error::unsupported(
        Op::ValidateRootfs,
        "rootfs " + real +
            " is on a Windows drive mount (drvfs/9p). That filesystem cannot "
            "represent device nodes, so creating /dev/null inside the "
            "container fails with a misleading EPERM. Put the rootfs on WSL's "
            "native ext4, e.g. under your home directory - see "
            "docs/getting-started.md"));
  }

  // An empty entrypoint is a caller error rather than a rootfs problem, but
  // checking it here is what makes the presence check below possible at all.
  if (entrypoint.empty()) {
    return Err(Error::invalid(Op::ValidateRootfs,
                              "no entrypoint was given for the container"));
  }

  // Only an absolute entrypoint can be checked: a bare "sh" is resolved
  // against the container's PATH at execve time, which cannot be evaluated
  // from out here. Saying nothing is better than guessing wrong.
  if (entrypoint[0] == '/') {
    const std::string full = real + entrypoint;
    struct ::stat st {};
    if (::stat(full.c_str(), &st) != 0) {
      return Err(Error::invalid(
          Op::ValidateRootfs,
          "entrypoint " + entrypoint + " does not exist inside the rootfs (" +
              full +
              "). It must exist in the CONTAINER's filesystem, not the "
              "host's"));
    }
    if (!S_ISREG(st.st_mode)) {
      return Err(Error::invalid(
          Op::ValidateRootfs, "entrypoint " + entrypoint +
                                  " inside the rootfs is not a regular file"));
    }
    if ((st.st_mode & 0111) == 0) {
      return Err(Error::invalid(
          Op::ValidateRootfs,
          "entrypoint " + entrypoint + " inside the rootfs is not executable"));
    }
  }

  return Ok();
}

}  // namespace mc
