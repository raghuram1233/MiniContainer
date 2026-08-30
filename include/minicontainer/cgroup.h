// SPDX-License-Identifier: MIT
//
// MiniContainer - Tier 2: cgroup v2 resource limits.
//
// ALL PARENT-SIDE. The child never touches a cgroup file; by the time it runs
// it is already inside its cgroup, either because clone3 put it there with
// CLONE_INTO_CGROUP or because the parent wrote its pid to cgroup.procs.
//
// PROBE, NEVER ASSUME
// -------------------
// Whether a controller is usable in our subtree varies by host and is not
// something to hard-code. The Ubuntu-24.04 WSL distro (systemd running) has
// "cpu memory pids" delegated; the docker-desktop distro has an EMPTY
// cgroup.subtree_control even though both present as cgroup v2. So every
// controller is probed, and a limit whose controller is unavailable produces
// a clear Op::Unsupported error naming the controller - never a silently
// missing limit.
//
// THE NO-INTERNAL-PROCESS RULE
// ----------------------------
// cgroup v2 forbids a cgroup from holding both processes and controller-
// enabled children. So the scope directory (<root>/minicontainer) holds no
// processes and only delegates downward; each container gets a leaf
// (<root>/minicontainer/<id>) that actually holds its process. This is also
// why EBUSY on a subtree_control write means "this cgroup contains
// processes" - the fix is always to move them to a child, never to force it.
//
// DELEGATION IS A WRITE TO THE PARENT
// -----------------------------------
// Enabling a controller for children writes "+memory +pids" to the PARENT's
// cgroup.subtree_control, not the child's, and it must be delegated at every
// level from the root down. Delegating at the root alone is not enough if our
// own scope does not re-delegate downward.
#pragma once

#include <sys/types.h>

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "minicontainer/config.h"
#include "minicontainer/errors.h"
#include "minicontainer/process.h"

namespace mc {

// Which controllers this host actually offers us, as probed at runtime.
struct CgroupSupport {
  bool unified_mount = false;  // /sys/fs/cgroup is a cgroup2 filesystem
  bool cpu = false;
  bool memory = false;
  bool pids = false;
  bool cpuset = false;
  bool io = false;

  // What <root>/cgroup.controllers reported, verbatim, for error messages.
  std::string available;
  // What <scope>/cgroup.subtree_control reported before we touched it.
  std::string delegated;

  [[nodiscard]] bool supports(std::string_view controller) const noexcept;
};

// Probes the host. Never writes anything.
Expected<CgroupSupport> detect_cgroup_support(const RuntimePaths& paths);

// A snapshot of a container's resource usage, for `stats`.
struct CgroupStats {
  std::uint64_t memory_current = 0;
  std::optional<std::uint64_t> memory_peak;
  std::optional<std::uint64_t> memory_max;  // nullopt when the file says "max"
  std::uint64_t cpu_usage_usec = 0;
  std::uint64_t pids_current = 0;
  std::optional<std::uint64_t> pids_max;
};

// ---------------------------------------------------------------------------
// CgroupManager - owns one container's leaf cgroup for its lifetime.
//
// Destroying the manager does NOT remove the cgroup: a cgroup outlives the
// process that created it (that is the point - `stats` reads it later). Call
// remove() explicitly, which is what Rollback does on a failed launch.
// ---------------------------------------------------------------------------
class CgroupManager {
 public:
  CgroupManager() = default;

  // Creates <cgroup_root>/<scope>/<id>, first delegating to the scope the
  // controllers these Resources actually need. Enabling only what is needed
  // keeps the failure surface small on hosts with partial delegation.
  static Expected<CgroupManager> create(const RuntimePaths& paths,
                                        const std::string& id,
                                        const Resources& resources);

  // Opens an existing container's cgroup, for stats and teardown.
  static Expected<CgroupManager> open(const RuntimePaths& paths,
                                      const std::string& id);

  [[nodiscard]] const std::string& path() const noexcept { return path_; }

  // Writes every limit the Resources actually set. A std::nullopt field is
  // skipped entirely - we never write a cgroup file we were not asked to.
  Expected<void> apply_limits(const Resources& resources);

  // An O_DIRECTORY fd for CLONE_INTO_CGROUP, so the child is born inside the
  // cgroup with no window in which it runs unconfined.
  [[nodiscard]] Expected<Fd> open_dir_fd() const;

  // Fallback for kernels without CLONE_INTO_CGROUP: write pid to
  // cgroup.procs. Logs that the brief unconfined window exists.
  Expected<void> attach(::pid_t pid);

  [[nodiscard]] Expected<CgroupStats> read_stats() const;

  // rmdir. Fails with EBUSY while any process remains inside, which is the
  // kernel telling us teardown ran too early rather than something to retry
  // blindly.
  Expected<void> remove();

  // Kills everything in the cgroup via cgroup.kill (kernel 5.14+), falling
  // back to signalling each pid in cgroup.procs. This is how `stop` can
  // guarantee it caught every descendant, not just the entrypoint.
  Expected<void> kill_all(int sig);

 private:
  std::string path_;
};

// Renders Resources into the exact strings the kernel expects, so the mapping
// is unit-testable without touching /sys/fs/cgroup. "max" is the literal the
// kernel wants for unlimited - never write 0, which for pids.max would forbid
// forking entirely.
struct CgroupLimitWrite {
  std::string file;        // "memory.max"
  std::string value;       // "268435456"
  std::string controller;  // "memory" - for the delegation check
};
std::vector<CgroupLimitWrite> cgroup_limit_writes(const Resources& resources);

}  // namespace mc
