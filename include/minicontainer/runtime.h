// SPDX-License-Identifier: MIT
//
// MiniContainer - Tier 3: lifecycle and the state store.
//
// This is the layer the CLI dispatches into. Runtime implements the RuntimeOps
// seam cli.h declares, and is the only place that knows a container has a
// lifetime spanning multiple processes: `run` creates it, a later `stop` in a
// different process must find it again.
//
// WHY A STATE FILE AT ALL
// -----------------------
// The `minicontainer` process that starts a container usually exits (detached
// mode) or is a different process from the one that stops it. The pid, cgroup
// path, and network allocation therefore have to outlive the launching
// process, or teardown cannot know what to remove. state.json is that record.
//
// WHY IT IS WRITTEN ATOMICALLY
// ----------------------------
// A crash midway through rewriting state.json would leave a truncated file,
// and a container whose state cannot be parsed is a container whose cgroup and
// veth can never be cleaned up. syscall.h's write_file_atomic (write to .tmp,
// fsync, rename) makes a partial write impossible to observe.
//
// PID REUSE IS THE HAZARD
// -----------------------
// A recorded pid is not proof the container is alive: the kernel recycles
// pids, and a stale record can point at an unrelated process. Every liveness
// check therefore verifies the pid's start time against the recorded one
// before believing it, and stop/kill prefer the cgroup (which cannot be
// confused) over the raw pid.
#pragma once

#include <sys/types.h>

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "minicontainer/cgroup.h"
#include "minicontainer/cli.h"
#include "minicontainer/config.h"
#include "minicontainer/errors.h"
#include "minicontainer/json.h"
#include "minicontainer/network.h"

namespace mc {

enum class ContainerStatus {
  Created,  // created, never started
  Running,
  Stopped,  // exited or was killed; the record and cgroup still exist
};

const char* container_status_name(ContainerStatus s) noexcept;
ContainerStatus container_status_from_string(std::string_view s) noexcept;

// One container's persisted record. Serialised to
// <state_root>/<id>/state.json.
struct ContainerState {
  std::string id;
  std::string name;
  ContainerStatus status = ContainerStatus::Created;
  ::pid_t pid = -1;

  // Guards against pid reuse: /proc/<pid>/stat field 22, which is unique to
  // this incarnation of the pid.
  std::uint64_t pid_start_time = 0;

  std::string created_at;   // ISO-8601 UTC millis: 2026-08-30T12:34:56.789Z
  std::string started_at;   // empty until started
  std::string finished_at;  // empty until it exits
  int exit_code = 0;
  int term_signal = 0;  // non-zero when killed by a signal

  std::string cgroup_path;
  NetworkAllocation network;
  ContainerConfig config;  // the full spec, so `inspect` needs nothing else

  [[nodiscard]] Json to_json() const;
  static Expected<ContainerState> from_json(const Json& j);
};

// ---------------------------------------------------------------------------
// StateStore - the on-disk registry under RuntimePaths::state_root.
// ---------------------------------------------------------------------------
class StateStore {
 public:
  explicit StateStore(RuntimePaths paths);

  Expected<void> save(const ContainerState& state);
  [[nodiscard]] Expected<ContainerState> load(const std::string& id) const;
  [[nodiscard]] Expected<std::vector<ContainerState>> list() const;
  Expected<void> remove(const std::string& id);

  // Accepts a full id, a unique id prefix, or a name - the resolution every
  // command taking a NAME argument needs. An ambiguous prefix is an error
  // naming the candidates rather than an arbitrary pick.
  [[nodiscard]] Expected<ContainerState> resolve(
      const std::string& name_or_id) const;

  // True when the recorded pid is alive AND is still the same incarnation.
  [[nodiscard]] bool is_alive(const ContainerState& state) const noexcept;

  // Reconciles a record whose process died without anyone observing it, so
  // `ps` never reports a container as Running when it is not.
  Expected<ContainerState> refresh(const ContainerState& state);

  [[nodiscard]] const RuntimePaths& paths() const noexcept { return paths_; }

 private:
  RuntimePaths paths_;
};

// Reads /proc/<pid>/stat field 22. Returns nullopt when the pid is gone.
std::optional<std::uint64_t> read_pid_start_time(::pid_t pid) noexcept;

// ---------------------------------------------------------------------------
// Runtime - what the CLI dispatches into.
// ---------------------------------------------------------------------------
class Runtime : public RuntimeOps {
 public:
  explicit Runtime(RuntimePaths paths);

  // Creates the container and waits for it, unless config.detach. Returns the
  // entrypoint's own exit status, which main() forwards - so `minicontainer
  // run ... /bin/false` exits 1 because the guest did, not because we failed.
  Expected<int> run(const ContainerConfig& config);

  Expected<std::string> create(const ContainerConfig& config);
  Expected<int> start(const std::string& target, bool wait);

  // SIGTERM, then SIGKILL after timeout_sec. Signals the whole cgroup, not
  // just the entrypoint, so a shell's children go too.
  Expected<void> stop(const std::string& target, int timeout_sec);
  Expected<void> kill(const std::string& target, int sig);

  Expected<std::vector<ContainerState>> ps(bool all);
  Expected<ContainerState> inspect(const std::string& target);
  Expected<CgroupStats> stats(const std::string& target);
  Expected<void> remove(const std::string& target, bool force);

  // Writes the container's captured output to `out`. Only a detached container
  // has any: an attached run sends its output straight to the caller's
  // terminal, so there is nothing to replay. `follow` tails the file until the
  // container exits, the way `tail -f` would.
  Expected<void> logs(const std::string& target, bool follow, int out_fd);

  // Joins the container's namespaces with setns and execs argv inside it.
  Expected<int> exec(const std::string& target,
                     const std::vector<std::string>& argv,
                     const std::vector<std::string>& env,
                     const std::string& workdir);

  // Removes the cgroup, network, and state directory. Best-effort: it reports
  // what it could not remove instead of stopping at the first failure and
  // leaking the rest.
  Expected<void> cleanup(ContainerState& state);

  [[nodiscard]] StateStore& store() noexcept { return store_; }

 private:
  RuntimePaths paths_;
  StateStore store_;
};

// Rendering helpers, kept out of Runtime so they can be unit-tested without a
// state directory.
std::string format_ps_table(const std::vector<ContainerState>& states);
std::string format_inspect(const ContainerState& state, bool json);
std::string format_stats(const ContainerState& state, const CgroupStats& stats,
                         bool json);

// "3 minutes ago", for the ps STATUS column.
std::string format_relative_time(const std::string& iso8601);

}  // namespace mc
