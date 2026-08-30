// SPDX-License-Identifier: MIT
//
// MiniContainer - the container lifecycle.
//
// This is the layer the CLI dispatches into, and the only one that knows a
// container outlives the process that started it. Everything below it deals in
// a single operation; this file deals in "a container exists, and here is what
// may be done to it next".
//
// THE THREE-STATE MODEL
// ---------------------
// Created -> Running -> Stopped, and no other transitions. `create` records a
// container without starting it, `start` launches one, `run` is the two
// together plus a wait. Keeping create and start separate is what lets a name
// and config be allocated and inspected before committing to running, and it
// is how `run --detach` and `start` end up sharing one code path.
//
// WHY stop() SIGNALS THE CGROUP, NOT THE PID
// ------------------------------------------
// The entrypoint is usually a shell, and a shell's children are not the
// entrypoint. Signalling the pid alone leaves them running, holding the
// cgroup, so the later rmdir fails with EBUSY and the container can never be
// removed. The cgroup knows every process inside it by construction, which is
// why it is the thing to signal whenever one exists.
//
// TEARDOWN IS BEST-EFFORT AND SAYS SO
// -----------------------------------
// cleanup() removes a cgroup, a veth, iptables rules, and a state directory.
// Any of them may already be gone, and stopping at the first failure would
// strand the rest forever - there is no later pass that would pick them up. So
// every step runs, and the failures are reported together.
#include <fcntl.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>

#include <cerrno>
#include <cstdio>
#include <string>
#include <utility>
#include <vector>

#include "minicontainer/cgroup.h"
#include "minicontainer/container.h"
#include "minicontainer/errors.h"
#include "minicontainer/filesystem.h"
#include "minicontainer/logging.h"
#include "minicontainer/network.h"
#include "minicontainer/process.h"
#include "minicontainer/runtime.h"

namespace mc {

namespace {

// state_store.cpp has an identical helper in its own anonymous namespace.
// Sharing it would mean exporting a timestamp function from the state store,
// which is not its job; a dozen lines is the cheaper duplication.
std::string now_iso8601() {
  struct ::timespec ts {};
  ::clock_gettime(CLOCK_REALTIME, &ts);
  struct ::tm tm {};
  ::gmtime_r(&ts.tv_sec, &tm);
  // Generously sized: the formatted timestamp is 24 characters, but GCC's
  // -Wformat-truncation reasons about the full int range of each field rather
  // than the range a struct tm can actually hold, so a tight buffer trips it.
  char buf[128];
  std::snprintf(buf, sizeof(buf), "%04d-%02d-%02dT%02d:%02d:%02d.%03ldZ",
                tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour,
                tm.tm_min, tm.tm_sec, static_cast<long>(ts.tv_nsec / 1000000));
  return buf;
}

// Every address currently handed out, so allocate_ip does not reissue one.
std::vector<std::string> addresses_in_use(const StateStore& store) {
  std::vector<std::string> taken;
  Expected<std::vector<ContainerState>> all = store.list();
  if (!all) {
    return taken;  // A listing failure must not block starting a container.
  }
  for (const ContainerState& s : *all) {
    if (!s.network.ip_cidr.empty()) {
      taken.push_back(s.network.ip_cidr);
    }
  }
  return taken;
}

std::string join_failures(const std::vector<std::string>& failures) {
  std::string all;
  for (const std::string& f : failures) {
    if (!all.empty()) {
      all += "; ";
    }
    all += f;
  }
  return all;
}

}  // namespace

Runtime::Runtime(RuntimePaths paths)
    : paths_(std::move(paths)), store_(paths_) {}

Expected<std::string> Runtime::create(const ContainerConfig& config) {
  ContainerConfig cfg = config;
  cfg.apply_defaults();
  MC_CHECK(cfg.validate());

  // Filesystem-dependent checks that ContainerConfig::validate() cannot do,
  // run now so `create` fails immediately rather than at `start`.
  MC_CHECK(validate_rootfs(cfg.rootfs_path,
                           cfg.args.empty() ? std::string() : cfg.args[0]));

  // A duplicate name would make resolve() ambiguous forever afterwards.
  if (Expected<ContainerState> existing = store_.resolve(cfg.name); existing) {
    return Err(Error::invalid(Op::ValidateConfig,
                              "a container named '" + cfg.name +
                                  "' already exists (id " + existing->id +
                                  "); remove it or choose another --name"));
  }

  ContainerState state;
  state.id = cfg.id;
  state.name = cfg.name;
  state.status = ContainerStatus::Created;
  state.created_at = now_iso8601();
  state.config = cfg;

  MC_CHECK(store_.save(state));
  return state.id;
}

Expected<int> Runtime::start(const std::string& target, bool wait) {
  ContainerState state = MC_TRY(store_.resolve(target));

  if (state.status == ContainerStatus::Running && store_.is_alive(state)) {
    return Err(Error::invalid(
        Op::Internal, "container " + state.name + " is already running"));
  }

  ContainerConfig cfg = state.config;
  if (cfg.network.mode == NetworkMode::Bridge &&
      !cfg.network.container_ip.has_value()) {
    cfg.network.container_ip =
        MC_TRY(allocate_ip(cfg.network, addresses_in_use(store_)));
  }

  LaunchResult launched = MC_TRY(launch_container(cfg, paths_));

  state.pid = launched.pid;
  state.pid_start_time = read_pid_start_time(launched.pid).value_or(0);
  state.status = ContainerStatus::Running;
  state.started_at = now_iso8601();
  state.cgroup_path = launched.cgroup_path;
  state.config = cfg;
  if (cfg.network.mode == NetworkMode::Bridge) {
    state.network.veth_host = launched.veth_host;
    state.network.veth_container = "eth0";
    state.network.bridge = cfg.network.bridge_name;
    state.network.gateway = cfg.network.gateway_ip;
    state.network.ip_cidr = cfg.network.container_ip.value_or(std::string());
    state.network.nat_configured = cfg.network.enable_nat;
    state.network.published = cfg.network.ports;
  }
  MC_CHECK(store_.save(state));

  if (!wait) {
    return 0;
  }

  // The launching process is the container's parent, so it is the only process
  // that can wait for it. That is also why --detach cannot report an exit
  // code: nobody is left to observe one.
  ExitStatus status = MC_TRY(wait_for(launched.pid));

  state.status = ContainerStatus::Stopped;
  state.finished_at = now_iso8601();
  state.exit_code = status.exited ? status.code : 0;
  state.term_signal = status.signaled ? status.signal : 0;
  MC_CHECK(store_.save(state));

  if (state.config.remove_on_exit) {
    MC_CHECK(cleanup(state));
  }
  return status.to_shell_code();
}

Expected<int> Runtime::run(const ContainerConfig& config) {
  const std::string id = MC_TRY(create(config));
  Expected<int> code = start(id, !config.detach);

  if (!code) {
    // A container recorded but never started would otherwise sit in the store
    // forever, since nothing else knows it exists.
    Expected<ContainerState> state = store_.load(id);
    if (state) {
      (void)cleanup(*state);
    }
    return code;
  }

  if (config.detach) {
    std::fprintf(stdout, "%s\n", id.c_str());
  }
  return code;
}

Expected<void> Runtime::stop(const std::string& target, int timeout_sec) {
  ContainerState state = MC_TRY(store_.resolve(target));
  if (!store_.is_alive(state)) {
    // Already gone. Reconcile the record rather than reporting an error: the
    // user asked for it to be stopped, and it is.
    ContainerState refreshed = MC_TRY(store_.refresh(state));
    return store_.save(refreshed);
  }

  MC_CHECK(kill(target, SIGTERM));

  // Poll rather than waitpid: this process is usually not the container's
  // parent, so it cannot wait on it at all.
  for (int elapsed_ms = 0; elapsed_ms < timeout_sec * 1000; elapsed_ms += 100) {
    if (!store_.is_alive(state)) {
      ContainerState refreshed = MC_TRY(store_.refresh(state));
      return store_.save(refreshed);
    }
    ::usleep(100 * 1000);
  }

  MC_LOG_WARN("container " << state.name << " did not exit within "
                           << timeout_sec << "s; sending SIGKILL");
  MC_CHECK(kill(target, SIGKILL));

  ContainerState refreshed = MC_TRY(store_.refresh(state));
  return store_.save(refreshed);
}

Expected<void> Runtime::kill(const std::string& target, int sig) {
  ContainerState state = MC_TRY(store_.resolve(target));
  if (!store_.is_alive(state)) {
    return Err(Error::invalid(Op::SignalChild,
                              "container " + state.name + " is not running"));
  }

  // Prefer the cgroup: it contains every descendant, and it cannot be confused
  // by pid reuse the way a bare pid can.
  if (!state.cgroup_path.empty()) {
    Expected<CgroupManager> cg = CgroupManager::open(paths_, state.id);
    if (cg) {
      return cg->kill_all(sig);
    }
  }

  // No cgroup (no resource limits were set), so fall back to the process
  // group - still better than the pid alone, since it catches the shell's
  // children.
  if (::kill(-state.pid, sig) != 0 && errno == ESRCH) {
    if (::kill(state.pid, sig) != 0) {
      return Err(Error::syscall(Op::SignalChild, "kill", errno,
                                "signalling container " + state.name));
    }
  }
  return Ok();
}

Expected<std::vector<ContainerState>> Runtime::ps(bool all) {
  std::vector<ContainerState> states = MC_TRY(store_.list());

  std::vector<ContainerState> out;
  for (ContainerState& s : states) {
    // Reconcile before reporting: a container whose process died without
    // anyone observing it must not be listed as Running.
    Expected<ContainerState> fresh = store_.refresh(s);
    ContainerState current = fresh ? *fresh : s;
    if (fresh && current.status != s.status) {
      (void)store_.save(current);
    }
    if (all || current.status == ContainerStatus::Running) {
      out.push_back(current);
    }
  }
  return out;
}

Expected<ContainerState> Runtime::inspect(const std::string& target) {
  ContainerState state = MC_TRY(store_.resolve(target));
  return store_.refresh(state);
}

Expected<CgroupStats> Runtime::stats(const std::string& target) {
  ContainerState state = MC_TRY(store_.resolve(target));
  if (state.cgroup_path.empty()) {
    return Err(Error::invalid(
        Op::ReadCgroupStat,
        "container " + state.name +
            " has no cgroup, so there are no statistics to read. A cgroup is "
            "only created when at least one resource limit is set"));
  }
  CgroupManager cg = MC_TRY(CgroupManager::open(paths_, state.id));
  return cg.read_stats();
}

Expected<void> Runtime::remove(const std::string& target, bool force) {
  ContainerState state = MC_TRY(store_.resolve(target));

  if (store_.is_alive(state)) {
    if (!force) {
      return Err(Error::invalid(
          Op::RemoveState,
          "container " + state.name +
              " is still running; stop it first, or pass --force"));
    }
    MC_CHECK(kill(target, SIGKILL));
    // Give the kernel a moment to reap it, or the cgroup rmdir below fails
    // with EBUSY on a process that is already on its way out.
    for (int i = 0; i < 50 && store_.is_alive(state); ++i) {
      ::usleep(100 * 1000);
    }
  }

  return cleanup(state);
}

Expected<void> Runtime::cleanup(ContainerState& state) {
  std::vector<std::string> failures;

  if (!state.cgroup_path.empty()) {
    Expected<CgroupManager> cg = CgroupManager::open(paths_, state.id);
    if (cg) {
      if (Expected<void> r = cg->remove(); !r) {
        failures.push_back("cgroup: " + r.error().message());
      }
    }
  }

  if (!state.network.veth_host.empty()) {
    if (Expected<void> r = teardown_network(state.network); !r) {
      failures.push_back("network: " + r.error().message());
    }
  }

  if (Expected<void> r = store_.remove(state.id); !r) {
    failures.push_back("state: " + r.error().message());
  }

  if (!failures.empty()) {
    return Err(Error::invalid(
        Op::RemoveState,
        "container " + state.name +
            " was only partly removed: " + join_failures(failures)));
  }
  return Ok();
}

Expected<void> Runtime::logs(const std::string& target, bool follow,
                             int out_fd) {
  ContainerState state = MC_TRY(store_.resolve(target));
  const std::string path = paths_.log_dir(state.id) + "/output.log";

  Fd in(::open(path.c_str(), O_RDONLY | O_CLOEXEC));
  if (!in.valid()) {
    if (errno == ENOENT) {
      // Not a failure of logs() so much as a consequence of how the container
      // was started, so say which - "no such file" would send the user looking
      // for a bug that is not there.
      return Err(Error::invalid(
          Op::ReadFile,
          "container " + state.name +
              " has no captured output. Only a detached container (`run -d`) "
              "is captured; an attached run writes straight to your terminal"));
    }
    return Err(Error::syscall(Op::OpenFile, "open", errno,
                              "reading container logs from " + path));
  }

  char buf[8192];
  for (;;) {
    const ssize_t n = ::read(in.get(), buf, sizeof(buf));
    if (n < 0) {
      if (errno == EINTR) {
        continue;
      }
      return Err(Error::syscall(Op::ReadFile, "read", errno, path));
    }
    if (n > 0) {
      ssize_t written = 0;
      while (written < n) {
        const ssize_t w = ::write(out_fd, buf + written,
                                  static_cast<std::size_t>(n - written));
        if (w < 0) {
          if (errno == EINTR) {
            continue;
          }
          return Err(Error::syscall(Op::WriteFile, "write", errno,
                                    "writing container logs to stdout"));
        }
        written += w;
      }
      continue;
    }

    // n == 0: end of file.
    if (!follow) {
      return Ok();
    }
    // Follow mode. Stop once the container is gone, otherwise there would be
    // no way out of this loop but Ctrl-C - and a `logs -f` on an exited
    // container that never returns is a worse bug than a missed final line.
    if (!store_.is_alive(state)) {
      return Ok();
    }
    ::usleep(200 * 1000);
  }
}

Expected<int> Runtime::exec(const std::string& target,
                            const std::vector<std::string>& argv,
                            const std::vector<std::string>& env,
                            const std::string& workdir) {
  ContainerState state = MC_TRY(store_.resolve(target));
  if (!store_.is_alive(state)) {
    return Err(Error::invalid(Op::JoinNamespace,
                              "container " + state.name + " is not running"));
  }
  if (argv.empty()) {
    return Err(Error::invalid(Op::ParseArgs, "exec needs a command to run"));
  }

  // Open every namespace BEFORE joining any of them: once the mount namespace
  // is joined, /proc/<pid>/ns/... resolves against the CONTAINER's /proc, and
  // the remaining handles could no longer be opened.
  const NsType kOrder[] = {NsType::User, NsType::Ipc, NsType::Uts,
                           NsType::Net,  NsType::Pid, NsType::Mount};
  std::vector<std::pair<NsType, Fd>> handles;
  for (NsType t : kOrder) {
    Expected<Fd> fd = open_namespace(state.pid, t);
    if (!fd) {
      // Not every container has every namespace - host networking means no
      // netns, and there is no userns unless it was asked for - so a missing
      // one is expected rather than an error.
      continue;
    }
    handles.emplace_back(t, std::move(*fd));
  }

  // User namespace first (it is first in kOrder): it owns the others, and
  // joining it after them would be refused.
  for (auto& [type, fd] : handles) {
    MC_CHECK(join_namespace(fd, type));
  }

  // setns(CLONE_NEWPID) affects only CHILDREN of the caller - this process
  // stays in its own PID namespace. So the fork is not an implementation
  // detail; it is the only way to get a process actually inside the
  // container's PID namespace.
  const ::pid_t child = ::fork();
  if (child < 0) {
    return Err(Error::syscall(Op::JoinNamespace, "fork", errno,
                              "creating the exec process"));
  }

  if (child == 0) {
    if (!workdir.empty() && ::chdir(workdir.c_str()) != 0) {
      ::_exit(126);
    }
    std::vector<char*> cargv;
    cargv.reserve(argv.size() + 1);
    for (const std::string& a : argv) {
      cargv.push_back(const_cast<char*>(a.c_str()));
    }
    cargv.push_back(nullptr);

    std::vector<char*> cenv;
    cenv.reserve(env.size() + 1);
    for (const std::string& e : env) {
      cenv.push_back(const_cast<char*>(e.c_str()));
    }
    cenv.push_back(nullptr);

    ::execvpe(cargv[0], cargv.data(), cenv.data());
    // 127 is the shell's convention for "command not found", which is what
    // this almost always is.
    ::_exit(127);
  }

  ExitStatus status = MC_TRY(wait_for(child));
  return status.to_shell_code();
}

}  // namespace mc
