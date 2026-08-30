// SPDX-License-Identifier: MIT
//
// MiniContainer - Tier 2: cgroup v2 resource limits. Implementation.
// See include/minicontainer/cgroup.h for the contract; the three facts that
// shape this file are repeated there at length:
//
//   1. Everything here is PARENT-side. Ordinary C++, ordinary allocation.
//   2. Nothing about controller availability is assumed - every controller is
//      probed, because the same "cgroup v2" host can delegate everything
//      (Ubuntu-24.04 + systemd) or nothing (docker-desktop's WSL distro).
//   3. The scope cgroup never holds a process; only leaves do. That is the
//      no-internal-process rule, and it is why EBUSY on a subtree_control
//      write is a diagnosis rather than something to retry.
//
// A note on what is deliberately NOT here: there is no retry loop anywhere in
// this file. EBUSY from subtree_control means "move the processes"; EBUSY from
// rmdir means "the container has not actually exited yet". Spinning on either
// converts a precise, actionable error into a timeout.

#include "minicontainer/cgroup.h"

#include <sys/stat.h>
#include <sys/types.h>
#include <sys/vfs.h>

#include <fcntl.h>
#include <signal.h>
#include <unistd.h>

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <cstdlib>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "minicontainer/logging.h"
#include "minicontainer/syscall.h"

namespace mc {
namespace {

// CGROUP2_SUPER_MAGIC. Spelled out rather than pulled from <linux/magic.h> so
// this file does not depend on kernel headers being installed.
constexpr long kCgroup2SuperMagic = 0x63677270;  // "cgrp"

std::string_view trim(std::string_view s) {
  const char* kWs = " \t\r\n";
  std::size_t b = s.find_first_not_of(kWs);
  if (b == std::string_view::npos)
    return {};
  std::size_t e = s.find_last_not_of(kWs);
  return s.substr(b, e - b + 1);
}

// Splits a kernel-style space-separated controller list.
std::vector<std::string_view> split_ws(std::string_view s) {
  std::vector<std::string_view> out;
  std::size_t i = 0;
  while (i < s.size()) {
    while (i < s.size() && std::isspace(static_cast<unsigned char>(s[i])))
      ++i;
    std::size_t start = i;
    while (i < s.size() && !std::isspace(static_cast<unsigned char>(s[i])))
      ++i;
    if (i > start)
      out.push_back(s.substr(start, i - start));
  }
  return out;
}

bool list_contains(std::string_view list, std::string_view token) {
  for (std::string_view t : split_ws(list)) {
    if (t == token)
      return true;
  }
  return false;
}

std::string scope_path(const RuntimePaths& paths) {
  return paths.cgroup_root + "/" + paths.cgroup_scope;
}

std::string parent_of(const std::string& path) {
  std::size_t slash = path.find_last_of('/');
  if (slash == std::string::npos)
    return ".";
  if (slash == 0)
    return "/";
  return path.substr(0, slash);
}

// Reads a cgroup attribute file, treating "the file does not exist" as an
// answer rather than a failure. A missing attribute file means its controller
// is not delegated here, which for statistics is an absent number - but for a
// *write* it is a hard error, so only the read paths use this.
Expected<std::optional<std::string>> read_attr(const std::string& path, Op op) {
  Expected<std::string> r = read_file(path, op);
  if (r)
    return std::optional<std::string>(std::move(r).value());
  if (r.error().err() == ENOENT)
    return std::optional<std::string>{};
  return Err(std::move(r).error());
}

Expected<std::uint64_t> parse_u64(std::string_view text,
                                  const std::string& path) {
  std::string_view t = trim(text);
  if (t.empty()) {
    return Err(Error::invalid(Op::ReadCgroupStat, path + ": empty value"));
  }
  std::string owned(t);
  errno = 0;
  char* end = nullptr;
  unsigned long long v = std::strtoull(owned.c_str(), &end, 10);
  if (errno != 0 || end == owned.c_str() || *end != '\0') {
    return Err(Error::invalid(Op::ReadCgroupStat,
                              path + ": not an integer: '" + owned + "'"));
  }
  return static_cast<std::uint64_t>(v);
}

// cgroup v2 writes the literal "max" for "no limit". That is NOT the same as
// 0, and mapping it onto 0 here would make an unconstrained container look
// like one that may not allocate at all.
Expected<std::optional<std::uint64_t>> parse_max_or_u64(
    std::string_view text, const std::string& path) {
  if (trim(text) == "max")
    return std::optional<std::uint64_t>{};
  return std::optional<std::uint64_t>(MC_TRY(parse_u64(text, path)));
}

// cpu.stat is a flat "key value" table; we want usage_usec. Its absence means
// the cpu controller is not delegated, which read_stats reports as 0 rather
// than as a failure.
Expected<std::uint64_t> parse_cpu_usage_usec(std::string_view content,
                                             const std::string& path) {
  std::size_t pos = 0;
  while (pos < content.size()) {
    std::size_t eol = content.find('\n', pos);
    std::string_view line = content.substr(
        pos, (eol == std::string_view::npos ? content.size() : eol) - pos);
    constexpr std::string_view kKey = "usage_usec";
    std::string_view l = trim(line);
    if (l.size() > kKey.size() && l.substr(0, kKey.size()) == kKey &&
        std::isspace(static_cast<unsigned char>(l[kKey.size()]))) {
      return parse_u64(l.substr(kKey.size()), path);
    }
    if (eol == std::string_view::npos)
      break;
    pos = eol + 1;
  }
  return static_cast<std::uint64_t>(0);
}

// The distinct controllers these Resources need, in first-mention order.
std::vector<std::string> needed_controllers(const Resources& resources) {
  std::vector<std::string> out;
  for (const CgroupLimitWrite& w : cgroup_limit_writes(resources)) {
    if (std::find(out.begin(), out.end(), w.controller) == out.end())
      out.push_back(w.controller);
  }
  return out;
}

}  // namespace

// ---------------------------------------------------------------------------
// CgroupSupport
// ---------------------------------------------------------------------------
bool CgroupSupport::supports(std::string_view controller) const noexcept {
  if (controller == "cpu")
    return cpu;
  if (controller == "memory")
    return memory;
  if (controller == "pids")
    return pids;
  if (controller == "cpuset")
    return cpuset;
  if (controller == "io")
    return io;
  // An unknown controller is never "supported": answering true would let a
  // typo sail past the delegation check and fail later as a bare ENOENT.
  return false;
}

Expected<CgroupSupport> detect_cgroup_support(const RuntimePaths& paths) {
  CgroupSupport support;

  // Is this even a unified hierarchy? Checking the mount's magic is the only
  // reliable answer: a cgroup v1 layout also lives at /sys/fs/cgroup and also
  // has directories full of controller-ish files.
  struct ::statfs sfs {};
  if (::statfs(paths.cgroup_root.c_str(), &sfs) != 0) {
    return Err(
        Error::syscall(Op::DetectCgroup, "statfs", errno, paths.cgroup_root));
  }
  if (static_cast<long>(sfs.f_type) != kCgroup2SuperMagic) {
    // Not a failure to probe - a successful probe with a negative answer. The
    // caller decides whether that is fatal, which it only is if a limit was
    // actually requested.
    return support;
  }
  support.unified_mount = true;

  // What the kernel compiled in and mounted here, verbatim, for messages.
  support.available = std::string(trim(MC_TRY(
      read_file(paths.cgroup_root + "/cgroup.controllers", Op::DetectCgroup))));

  // What is USABLE for our leaves is a narrower question than what the root
  // has. A controller must be delegated at every level from the root down, so
  // the honest probe is:
  //   * scope exists  -> <scope>/cgroup.controllers is authoritative: it is
  //                      exactly the set the scope may put in its own
  //                      subtree_control.
  //   * scope absent  -> <root>/cgroup.subtree_control, because that is what
  //                      <scope>/cgroup.controllers will contain the moment we
  //                      mkdir the scope.
  // Deriving the flags from <root>/cgroup.controllers instead would claim
  // cpuset on a host whose root delegates only "cpu memory pids" - and the
  // failure would surface as ENOENT on cpuset.cpus, which explains nothing.
  const std::string scope = scope_path(paths);
  std::string usable;
  if (is_directory(scope)) {
    support.delegated = std::string(trim(MC_TRY(
        read_file(scope + "/cgroup.subtree_control", Op::DetectCgroup))));
    usable = std::string(trim(
        MC_TRY(read_file(scope + "/cgroup.controllers", Op::DetectCgroup))));
  } else {
    usable = std::string(trim(MC_TRY(read_file(
        paths.cgroup_root + "/cgroup.subtree_control", Op::DetectCgroup))));
  }

  support.cpu = list_contains(usable, "cpu");
  support.memory = list_contains(usable, "memory");
  support.pids = list_contains(usable, "pids");
  support.cpuset = list_contains(usable, "cpuset");
  support.io = list_contains(usable, "io");

  MC_LOG_DEBUG("cgroup v2 at " << paths.cgroup_root << ": controllers='"
                               << support.available << "' usable-in-scope='"
                               << usable << "' scope-subtree_control='"
                               << support.delegated << "'");
  return support;
}

// ---------------------------------------------------------------------------
// cgroup_limit_writes - the pure heart of this module.
//
// Every entry here is something the caller explicitly asked for. A std::nullopt
// field produces NO entry at all, which is the difference between "leave this
// resource alone" and "set it to a limit that happens to be the default". We
// also never emit "0": for pids.max that would forbid forking outright, and for
// memory.max it would OOM-kill the container on its first allocation. The
// kernel's literal for unlimited is "max", and we only ever write it if asked.
// ---------------------------------------------------------------------------
std::vector<CgroupLimitWrite> cgroup_limit_writes(const Resources& resources) {
  std::vector<CgroupLimitWrite> writes;

  if (resources.memory_bytes.has_value()) {
    writes.push_back(
        {"memory.max", std::to_string(*resources.memory_bytes), "memory"});
  }
  // memory.swap.max is swap ON TOP OF memory.max, not a combined ceiling -
  // unlike cgroup v1's memsw.limit. Ordering it after memory.max also matches
  // how the kernel wants the pair set.
  if (resources.memory_swap_bytes.has_value()) {
    writes.push_back({"memory.swap.max",
                      std::to_string(*resources.memory_swap_bytes), "memory"});
  }
  // cpu.max is "<quota> <period>" in microseconds, in that order; reversed it
  // is still two valid integers, so the kernel accepts a nonsense limit
  // silently. Resources::cpu_max_value() owns that arithmetic and returns
  // nullopt for a non-positive cpus, which validate() has already rejected.
  if (std::optional<std::string> cpu_max = resources.cpu_max_value();
      cpu_max.has_value()) {
    writes.push_back({"cpu.max", *cpu_max, "cpu"});
  }
  if (resources.cpu_shares.has_value()) {
    writes.push_back(
        {"cpu.weight", std::to_string(*resources.cpu_shares), "cpu"});
  }
  if (resources.pids_max.has_value()) {
    writes.push_back({"pids.max", std::to_string(*resources.pids_max), "pids"});
  }
  if (resources.cpuset_cpus.has_value()) {
    writes.push_back({"cpuset.cpus", *resources.cpuset_cpus, "cpuset"});
  }

  return writes;
}

// ---------------------------------------------------------------------------
// CgroupManager
// ---------------------------------------------------------------------------
namespace {

Expected<void> check_id(const std::string& id) {
  if (id.empty())
    return Err(Error::invalid(Op::CreateCgroup, "empty container id"));
  // A '/' would let an id escape the scope directory, and the whole safety
  // argument for teardown is that we never touch anything outside it.
  if (id.find('/') != std::string::npos || id == "." || id == "..") {
    return Err(Error::invalid(
        Op::CreateCgroup,
        "container id '" + id + "' is not a single path component"));
  }
  return Ok();
}

}  // namespace

Expected<CgroupManager> CgroupManager::create(const RuntimePaths& paths,
                                              const std::string& id,
                                              const Resources& resources) {
  MC_CHECK(check_id(id));

  const CgroupSupport support = MC_TRY(detect_cgroup_support(paths));
  if (!support.unified_mount) {
    return Err(Error::unsupported(
        Op::CreateCgroup,
        paths.cgroup_root +
            " is not a cgroup v2 (unified) filesystem; MiniContainer does not "
            "implement cgroup v1. Boot with systemd.unified_cgroup_hierarchy=1 "
            "or mount cgroup2 there."));
  }

  const std::string scope = scope_path(paths);
  const std::vector<std::string> needed = needed_controllers(resources);

  // Fail BEFORE creating anything if a requested limit can never be applied.
  // A half-built cgroup that silently lacks memory.max is exactly the failure
  // mode docs/cgroups.md warns about.
  for (const std::string& c : needed) {
    if (support.supports(c))
      continue;
    std::string what = "cgroup controller '" + c + "' is not usable under " +
                       scope + "; " + paths.cgroup_root +
                       "/cgroup.controllers has '" + support.available + "'";
    if (!support.delegated.empty()) {
      what += " and " + scope + "/cgroup.subtree_control has '" +
              support.delegated + "'";
    }
    what +=
        ". A controller must be delegated at every level from the root down, "
        "so the root's own cgroup.subtree_control has to list it too.";
    return Err(Error::unsupported(Op::EnableController, std::move(what)));
  }

  MC_CHECK(make_directories(scope, Op::CreateCgroup));

  // Delegation is a write to the PARENT's subtree_control. Only the
  // controllers these Resources actually need are enabled: on a host with
  // partial delegation, enabling the full set would fail a container that only
  // ever wanted a memory limit.
  const std::string control = scope + "/cgroup.subtree_control";
  const std::string enabled =
      std::string(trim(MC_TRY(read_file(control, Op::EnableController))));
  std::string add;
  for (const std::string& c : needed) {
    if (list_contains(enabled, c))
      continue;
    if (!add.empty())
      add += ' ';
    add += '+';
    add += c;
  }

  if (!add.empty()) {
    Expected<void> w = write_file(control, add, Op::EnableController);
    if (!w) {
      const int err = w.error().err();
      if (err == EBUSY) {
        // Not transient, and not something a retry can fix: cgroup v2 refuses
        // to make a cgroup an internal node while it directly holds processes.
        return Err(Error::syscall(
            Op::EnableController, "write", EBUSY,
            control + " <- \"" + add + "\": " + scope +
                " holds processes directly, and cgroup v2 forbids a cgroup "
                "from having both member processes and controller-enabled "
                "children (the no-internal-process rule). Move those "
                "processes into a leaf cgroup first; retrying or forcing the "
                "write cannot succeed."));
      }
      return Err(std::move(w).error());
    }
    MC_LOG_DEBUG("delegated \"" << add << "\" to " << control);
  }

  const std::string leaf = scope + "/" + id;
  MC_CHECK(make_directories(leaf, Op::CreateCgroup));

  CgroupManager mgr;
  mgr.path_ = leaf;
  return mgr;
}

Expected<CgroupManager> CgroupManager::open(const RuntimePaths& paths,
                                            const std::string& id) {
  MC_CHECK(check_id(id));

  const std::string leaf = scope_path(paths) + "/" + id;
  if (!is_directory(leaf)) {
    return Err(Error::syscall(Op::OpenFile, "stat", ENOENT,
                              leaf + ": no such cgroup"));
  }

  CgroupManager mgr;
  mgr.path_ = leaf;
  return mgr;
}

Expected<void> CgroupManager::apply_limits(const Resources& resources) {
  if (path_.empty()) {
    return Err(Error::invalid(Op::WriteCgroupLimit,
                              "cgroup manager is not bound to a cgroup"));
  }

  for (const CgroupLimitWrite& entry : cgroup_limit_writes(resources)) {
    const std::string file = path_ + "/" + entry.file;
    Expected<void> w = write_file(file, entry.value, Op::WriteCgroupLimit);
    if (!w) {
      const int err = w.error().err();
      if (err == ENOENT) {
        // The file only exists once the controller is delegated by the PARENT.
        // A bare "ENOENT on memory.max" explains nothing; say what is missing
        // and exactly how to provide it.
        return Err(Error::unsupported(
            Op::WriteCgroupLimit,
            file + " does not exist: the '" + entry.controller +
                "' controller is not delegated to this cgroup. Enable it on "
                "the parent with: echo '+" +
                entry.controller + "' > " + parent_of(path_) +
                "/cgroup.subtree_control"));
      }
      return Err(std::move(w).error());
    }
    MC_LOG_DEBUG("cgroup limit " << entry.file << " = \"" << entry.value
                                 << "\" (" << entry.controller << ") on "
                                 << path_);
  }
  return Ok();
}

Expected<Fd> CgroupManager::open_dir_fd() const {
  if (path_.empty()) {
    return Err(Error::invalid(Op::OpenFile,
                              "cgroup manager is not bound to a cgroup"));
  }
  // O_DIRECTORY so this can never accidentally be a file, O_CLOEXEC so the fd
  // does not leak through the execve() that follows the clone3() it feeds.
  int fd = ::open(path_.c_str(), O_DIRECTORY | O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    return Err(Error::syscall(Op::OpenFile, "open", errno,
                              path_ + ", O_DIRECTORY|O_RDONLY|O_CLOEXEC"));
  }
  return Fd(fd);
}

Expected<void> CgroupManager::attach(::pid_t pid) {
  if (path_.empty()) {
    return Err(Error::invalid(Op::AttachCgroup,
                              "cgroup manager is not bound to a cgroup"));
  }

  // This is the FALLBACK path. With CLONE_INTO_CGROUP the child is born
  // inside the cgroup; here it already exists and has been running - briefly,
  // but genuinely - outside its limits. Say so, because "the memory limit did
  // not stop it" is otherwise a baffling report.
  MC_LOG_DEBUG("attaching pid "
               << pid << " to " << path_
               << " via cgroup.procs (CLONE_INTO_CGROUP was unavailable); the "
                  "process ran unconfined between clone() and this write");

  const std::string procs = path_ + "/cgroup.procs";
  Expected<void> w = write_file(procs, std::to_string(pid), Op::AttachCgroup);
  if (!w) {
    const int err = w.error().err();
    if (err == EBUSY) {
      return Err(Error::syscall(
          Op::AttachCgroup, "write", EBUSY,
          procs + " <- " + std::to_string(pid) + ": " + path_ +
              " has controllers enabled for its children, so it is an "
              "internal node and cgroup v2 will not let it hold a process "
              "(the no-internal-process rule). Attach to a leaf instead."));
    }
    if (err == ESRCH) {
      return Err(Error::syscall(
          Op::AttachCgroup, "write", ESRCH,
          procs + ": pid " + std::to_string(pid) + " no longer exists"));
    }
    return Err(std::move(w).error());
  }
  return Ok();
}

Expected<CgroupStats> CgroupManager::read_stats() const {
  if (path_.empty()) {
    return Err(Error::invalid(Op::ReadCgroupStat,
                              "cgroup manager is not bound to a cgroup"));
  }

  CgroupStats stats;

  // Every attribute below is read with read_attr, so a controller that is not
  // delegated yields an absent statistic rather than aborting the whole
  // snapshot. `stats` on a container with only a pids limit should still
  // report its pid counts.
  const std::string mem_current = path_ + "/memory.current";
  if (std::optional<std::string> v =
          MC_TRY(read_attr(mem_current, Op::ReadCgroupStat));
      v.has_value()) {
    stats.memory_current = MC_TRY(parse_u64(*v, mem_current));
  }

  // memory.peak is kernel 5.19+. Its absence is a kernel-version fact, not an
  // error, which is why the field is optional in the first place.
  const std::string mem_peak = path_ + "/memory.peak";
  if (std::optional<std::string> v =
          MC_TRY(read_attr(mem_peak, Op::ReadCgroupStat));
      v.has_value()) {
    stats.memory_peak = MC_TRY(parse_u64(*v, mem_peak));
  }

  const std::string mem_max = path_ + "/memory.max";
  if (std::optional<std::string> v =
          MC_TRY(read_attr(mem_max, Op::ReadCgroupStat));
      v.has_value()) {
    stats.memory_max = MC_TRY(parse_max_or_u64(*v, mem_max));
  }

  const std::string pids_current = path_ + "/pids.current";
  if (std::optional<std::string> v =
          MC_TRY(read_attr(pids_current, Op::ReadCgroupStat));
      v.has_value()) {
    stats.pids_current = MC_TRY(parse_u64(*v, pids_current));
  }

  const std::string pids_max = path_ + "/pids.max";
  if (std::optional<std::string> v =
          MC_TRY(read_attr(pids_max, Op::ReadCgroupStat));
      v.has_value()) {
    stats.pids_max = MC_TRY(parse_max_or_u64(*v, pids_max));
  }

  const std::string cpu_stat = path_ + "/cpu.stat";
  if (std::optional<std::string> v =
          MC_TRY(read_attr(cpu_stat, Op::ReadCgroupStat));
      v.has_value()) {
    stats.cpu_usage_usec = MC_TRY(parse_cpu_usage_usec(*v, cpu_stat));
  }

  return stats;
}

Expected<void> CgroupManager::remove() {
  if (path_.empty()) {
    return Err(Error::invalid(Op::RemoveCgroup,
                              "cgroup manager is not bound to a cgroup"));
  }

  if (::rmdir(path_.c_str()) == 0)
    return Ok();

  const int err = errno;
  if (err == ENOENT) {
    // Idempotent on purpose: remove() is what Rollback calls, and a rollback
    // that fails because the thing it wanted gone is already gone would mask
    // the real error that triggered the unwind.
    MC_LOG_DEBUG("cgroup " << path_ << " was already removed");
    return Ok();
  }
  if (err == EBUSY) {
    return Err(Error::syscall(
        Op::RemoveCgroup, "rmdir", EBUSY,
        path_ +
            ": the cgroup still contains processes. Signalling a container is "
            "not the same as it having exited - kill_all() and then wait for "
            "the processes to actually die before removing."));
  }
  return Err(Error::syscall(Op::RemoveCgroup, "rmdir", err, path_));
}

Expected<void> CgroupManager::kill_all(int sig) {
  if (path_.empty()) {
    return Err(Error::invalid(Op::SignalChild,
                              "cgroup manager is not bound to a cgroup"));
  }

  // cgroup.kill (kernel 5.14+) kills every member atomically, including
  // processes that forked after we started looking - which the pid loop below
  // cannot promise. It ALWAYS sends SIGKILL, so it is only correct here when
  // that is what the caller asked for; using it for SIGTERM would silently
  // upgrade a graceful stop into a hard kill.
  const std::string kill_file = path_ + "/cgroup.kill";
  if (sig == SIGKILL && path_exists(kill_file)) {
    Expected<void> w = write_file(kill_file, "1", Op::SignalChild);
    if (w)
      return Ok();
    if (w.error().err() != ENOENT)
      return Err(std::move(w).error());
    // Raced with removal; fall through to the pid loop.
  }

  const std::string procs = path_ + "/cgroup.procs";
  const std::string content = MC_TRY(read_file(procs, Op::SignalChild));

  std::size_t pos = 0;
  std::size_t signalled = 0;
  while (pos < content.size()) {
    std::size_t eol = content.find('\n', pos);
    std::string_view line = std::string_view(content).substr(
        pos, (eol == std::string::npos ? content.size() : eol) - pos);
    std::string_view t = trim(line);
    if (!t.empty()) {
      const std::uint64_t raw = MC_TRY(parse_u64(t, procs));
      const auto pid = static_cast<::pid_t>(raw);
      if (::kill(pid, sig) < 0) {
        // ESRCH is the normal outcome of a race we cannot avoid: the process
        // exited between reading cgroup.procs and signalling it. Anything
        // else is a real failure worth reporting.
        if (errno != ESRCH) {
          return Err(
              Error::syscall(Op::SignalChild, "kill", errno,
                             "pid " + std::to_string(pid) + " in " + path_));
        }
      } else {
        ++signalled;
      }
    }
    if (eol == std::string::npos)
      break;
    pos = eol + 1;
  }

  MC_LOG_DEBUG("signalled " << signalled << " process(es) in " << path_
                            << " with " << format_signal(sig)
                            << " (cgroup.kill unavailable or not applicable)");
  return Ok();
}

}  // namespace mc
