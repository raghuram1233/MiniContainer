// SPDX-License-Identifier: MIT
//
// MiniContainer - Tier 3: the on-disk container state store.
// Implementation of ContainerState and StateStore. See
// include/minicontainer/runtime.h for the contract and the rationale.
//
// WHAT THIS FILE IS RESPONSIBLE FOR
// ---------------------------------
// Turning one container's record into bytes and back without losing anything,
// and answering "is this record still true?" honestly. Everything else about a
// container's lifetime is somebody else's file; this one only has to be
// exactly right about persistence.
//
// THE TRAPS
// ---------
// 1. An unset std::optional is ABSENT from the JSON, never null and never 0.
//    Resources::memory_bytes means "do not write memory.max at all"; writing it
//    back as 0 would turn "no limit" into "zero bytes", which the kernel would
//    happily enforce by killing the container instantly.
//
// 2. Every write goes through write_file_atomic. A state.json truncated by a
//    crash is a container whose cgroup and veth can never be found again, and
//    therefore never cleaned up.
//
// 3. list() skips a container it cannot read rather than failing. One corrupt
//    record must not make `ps` useless for every other container on the host.
//
// 4. read_pid_start_time counts fields AFTER the last ')' in /proc/<pid>/stat.
//    Field 2 is the executable's comm, wrapped in parentheses, and it may
//    itself contain spaces and parentheses - a process named "foo bar) baz"
//    breaks any implementation that splits the line on whitespace. Field 22
//    (starttime) is what makes a recorded pid trustworthy: pids are recycled,
//    and a stale record pointing at a recycled pid would let us signal, or
//    report as Running, a completely unrelated process.

#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>

#include <dirent.h>
#include <unistd.h>

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <string>
#include <utility>
#include <vector>

#include "minicontainer/runtime.h"
#include "minicontainer/syscall.h"

namespace mc {

// ---------------------------------------------------------------------------
// ContainerStatus
// ---------------------------------------------------------------------------
const char* container_status_name(ContainerStatus s) noexcept {
  switch (s) {
    case ContainerStatus::Created:
      return "created";
    case ContainerStatus::Running:
      return "running";
    case ContainerStatus::Stopped:
      return "stopped";
  }
  return "created";
}

ContainerStatus container_status_from_string(std::string_view s) noexcept {
  if (s == "running")
    return ContainerStatus::Running;
  if (s == "stopped")
    return ContainerStatus::Stopped;
  // Anything unrecognised - including a status written by a future version -
  // reads back as Created, the state with the fewest resources attached to it.
  return ContainerStatus::Created;
}

namespace {

// ---------------------------------------------------------------------------
// Timestamps. logging.cpp has an identical helper in its own anonymous
// namespace; duplicating ten lines is cheaper than a header dependency from
// the state store onto the logger purely for a strftime call.
// ---------------------------------------------------------------------------
std::string iso8601_utc_millis() {
  timeval tv{};
  ::gettimeofday(&tv, nullptr);
  std::time_t secs = tv.tv_sec;
  std::tm tm_buf{};
  ::gmtime_r(&secs, &tm_buf);
  char buf[32];
  std::size_t n = std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%S", &tm_buf);
  int millis = static_cast<int>(tv.tv_usec / 1000);
  char full[40];
  std::snprintf(full, sizeof(full), "%.*s.%03dZ", static_cast<int>(n), buf,
                millis);
  return std::string(full);
}

// ---------------------------------------------------------------------------
// Enum <-> string for the config enums the state file has to carry. These are
// spelled out here rather than in config.cpp because they exist only for
// persistence: the CLI parses its own spellings.
// ---------------------------------------------------------------------------
const char* seccomp_mode_name(SeccompMode m) noexcept {
  switch (m) {
    case SeccompMode::Off:
      return "off";
    case SeccompMode::Default:
      return "default";
    case SeccompMode::Profile:
      return "profile";
  }
  return "default";
}

SeccompMode seccomp_mode_from_string(std::string_view s) noexcept {
  if (s == "off")
    return SeccompMode::Off;
  if (s == "profile")
    return SeccompMode::Profile;
  return SeccompMode::Default;
}

// ---------------------------------------------------------------------------
// Small serialisation helpers.
// ---------------------------------------------------------------------------
Json to_json(const std::vector<std::string>& values) {
  JsonArray arr;
  arr.reserve(values.size());
  for (const std::string& v : values)
    arr.emplace_back(v);
  return Json(std::move(arr));
}

std::vector<std::string> string_vector(const Json& j) {
  std::vector<std::string> out;
  for (const Json& item : j.as_array()) {
    if (item.type() == Json::Type::String)
      out.push_back(item.as_string());
  }
  return out;
}

// The optional writers are the heart of trap 1: they emit nothing at all when
// the option is unset, so from_json sees an absent key and leaves the optional
// unset in turn.
void put_optional_uint(JsonObject& obj, const char* key,
                       const std::optional<std::uint64_t>& value) {
  if (value.has_value())
    obj[key] = Json(*value);
}

void put_optional_double(JsonObject& obj, const char* key,
                         const std::optional<double>& value) {
  if (value.has_value())
    obj[key] = Json(*value);
}

void put_optional_string(JsonObject& obj, const char* key,
                         const std::optional<std::string>& value) {
  if (value.has_value())
    obj[key] = Json(*value);
}

std::optional<std::uint64_t> read_optional_uint(const Json& parent,
                                                const std::string& key) {
  if (!parent.contains(key))
    return std::nullopt;
  const Json& v = parent[key];
  if (v.type() != Json::Type::Number)
    return std::nullopt;
  // A negative value is not a limit we can represent, and as_uint() would hand
  // back its fallback of 0 - which this function would then wrap in an ENGAGED
  // optional, silently turning "no limit" into "a limit of zero bytes". The
  // kernel enforces that by killing the container the moment it allocates.
  // Absent is the only honest reading of a value we cannot represent.
  if (v.as_number() < 0)
    return std::nullopt;
  return v.as_uint();
}

std::optional<double> read_optional_double(const Json& parent,
                                           const std::string& key) {
  if (!parent.contains(key))
    return std::nullopt;
  const Json& v = parent[key];
  if (v.type() != Json::Type::Number)
    return std::nullopt;
  return v.as_number();
}

std::optional<std::string> read_optional_string(const Json& parent,
                                                const std::string& key) {
  if (!parent.contains(key))
    return std::nullopt;
  const Json& v = parent[key];
  if (v.type() != Json::Type::String)
    return std::nullopt;
  return v.as_string();
}

// ---------------------------------------------------------------------------
// PortMapping
// ---------------------------------------------------------------------------
Json port_to_json(const PortMapping& p) {
  JsonObject o;
  o["host_port"] = Json(static_cast<std::uint64_t>(p.host_port));
  o["container_port"] = Json(static_cast<std::uint64_t>(p.container_port));
  o["protocol"] = Json(p.protocol);
  return Json(std::move(o));
}

std::vector<PortMapping> ports_from_json(const Json& j) {
  std::vector<PortMapping> out;
  for (const Json& item : j.as_array()) {
    PortMapping p;
    p.host_port = static_cast<std::uint16_t>(item["host_port"].as_uint());
    p.container_port =
        static_cast<std::uint16_t>(item["container_port"].as_uint());
    const Json& proto = item["protocol"];
    p.protocol = proto.type() == Json::Type::String ? proto.as_string() : "tcp";
    out.push_back(std::move(p));
  }
  return out;
}

// ---------------------------------------------------------------------------
// Resources / NetworkConfig / SecurityConfig / ContainerConfig
// ---------------------------------------------------------------------------
Json resources_to_json(const Resources& r) {
  JsonObject o;
  put_optional_uint(o, "memory_bytes", r.memory_bytes);
  put_optional_uint(o, "memory_swap_bytes", r.memory_swap_bytes);
  put_optional_double(o, "cpus", r.cpus);
  put_optional_uint(o, "cpu_shares", r.cpu_shares);
  put_optional_uint(o, "pids_max", r.pids_max);
  put_optional_string(o, "cpuset_cpus", r.cpuset_cpus);
  return Json(std::move(o));
}

Resources resources_from_json(const Json& j) {
  Resources r;
  r.memory_bytes = read_optional_uint(j, "memory_bytes");
  r.memory_swap_bytes = read_optional_uint(j, "memory_swap_bytes");
  r.cpus = read_optional_double(j, "cpus");
  r.cpu_shares = read_optional_uint(j, "cpu_shares");
  r.pids_max = read_optional_uint(j, "pids_max");
  r.cpuset_cpus = read_optional_string(j, "cpuset_cpus");
  return r;
}

Json network_config_to_json(const NetworkConfig& n) {
  JsonObject o;
  o["mode"] = Json(network_mode_name(n.mode));
  o["bridge_name"] = Json(n.bridge_name);
  o["subnet_cidr"] = Json(n.subnet_cidr);
  o["gateway_ip"] = Json(n.gateway_ip);
  put_optional_string(o, "container_ip", n.container_ip);
  o["dns_servers"] = to_json(n.dns_servers);
  JsonArray ports;
  ports.reserve(n.ports.size());
  for (const PortMapping& p : n.ports)
    ports.push_back(port_to_json(p));
  o["ports"] = Json(std::move(ports));
  o["enable_nat"] = Json(n.enable_nat);
  return Json(std::move(o));
}

NetworkConfig network_config_from_json(const Json& j) {
  NetworkConfig n;
  n.mode = network_mode_from_string(j["mode"].as_string());
  if (j.contains("bridge_name"))
    n.bridge_name = j["bridge_name"].as_string();
  if (j.contains("subnet_cidr"))
    n.subnet_cidr = j["subnet_cidr"].as_string();
  if (j.contains("gateway_ip"))
    n.gateway_ip = j["gateway_ip"].as_string();
  n.container_ip = read_optional_string(j, "container_ip");
  // An absent dns_servers keeps the struct's default list; an explicitly empty
  // array means the user asked for no DNS servers, and that must survive.
  if (j.contains("dns_servers"))
    n.dns_servers = string_vector(j["dns_servers"]);
  n.ports = ports_from_json(j["ports"]);
  n.enable_nat = j["enable_nat"].as_bool(n.enable_nat);
  return n;
}

Json security_config_to_json(const SecurityConfig& s) {
  JsonObject o;
  o["cap_drop"] = to_json(s.cap_drop);
  o["cap_add"] = to_json(s.cap_add);
  o["seccomp"] = Json(seccomp_mode_name(s.seccomp));
  o["seccomp_profile_path"] = Json(s.seccomp_profile_path);
  o["no_new_privs"] = Json(s.no_new_privs);
  o["userns"] = Json(s.userns);
  o["userns_host_uid"] = Json(static_cast<std::uint64_t>(s.userns_host_uid));
  o["userns_host_gid"] = Json(static_cast<std::uint64_t>(s.userns_host_gid));
  o["userns_size"] = Json(static_cast<std::uint64_t>(s.userns_size));
  o["privileged"] = Json(s.privileged);
  o["readonly_rootfs"] = Json(s.readonly_rootfs);
  return Json(std::move(o));
}

SecurityConfig security_config_from_json(const Json& j) {
  SecurityConfig s;
  s.cap_drop = string_vector(j["cap_drop"]);
  s.cap_add = string_vector(j["cap_add"]);
  s.seccomp = seccomp_mode_from_string(j["seccomp"].as_string());
  s.seccomp_profile_path = j["seccomp_profile_path"].as_string();
  s.no_new_privs = j["no_new_privs"].as_bool(s.no_new_privs);
  s.userns = j["userns"].as_bool(s.userns);
  s.userns_host_uid = static_cast<std::uint32_t>(
      j["userns_host_uid"].as_uint(s.userns_host_uid));
  s.userns_host_gid = static_cast<std::uint32_t>(
      j["userns_host_gid"].as_uint(s.userns_host_gid));
  s.userns_size =
      static_cast<std::uint32_t>(j["userns_size"].as_uint(s.userns_size));
  s.privileged = j["privileged"].as_bool(s.privileged);
  s.readonly_rootfs = j["readonly_rootfs"].as_bool(s.readonly_rootfs);
  return s;
}

Json config_to_json(const ContainerConfig& c) {
  JsonObject o;
  o["id"] = Json(c.id);
  o["name"] = Json(c.name);
  o["hostname"] = Json(c.hostname);
  o["rootfs_path"] = Json(c.rootfs_path);
  o["args"] = to_json(c.args);
  o["env"] = to_json(c.env);
  o["working_dir"] = Json(c.working_dir);
  o["resources"] = resources_to_json(c.resources);
  o["network"] = network_config_to_json(c.network);
  o["security"] = security_config_to_json(c.security);
  o["bind_mounts"] = to_json(c.bind_mounts);
  o["tty"] = Json(c.tty);
  o["detach"] = Json(c.detach);
  o["remove_on_exit"] = Json(c.remove_on_exit);
  return Json(std::move(o));
}

ContainerConfig config_from_json(const Json& j) {
  ContainerConfig c;
  c.id = j["id"].as_string();
  c.name = j["name"].as_string();
  c.hostname = j["hostname"].as_string();
  c.rootfs_path = j["rootfs_path"].as_string();
  c.args = string_vector(j["args"]);
  c.env = string_vector(j["env"]);
  if (j.contains("working_dir"))
    c.working_dir = j["working_dir"].as_string();
  c.resources = resources_from_json(j["resources"]);
  c.network = network_config_from_json(j["network"]);
  c.security = security_config_from_json(j["security"]);
  c.bind_mounts = string_vector(j["bind_mounts"]);
  c.tty = j["tty"].as_bool();
  c.detach = j["detach"].as_bool();
  c.remove_on_exit = j["remove_on_exit"].as_bool();
  return c;
}

// ---------------------------------------------------------------------------
// NetworkAllocation
// ---------------------------------------------------------------------------
Json allocation_to_json(const NetworkAllocation& a) {
  JsonObject o;
  o["veth_host"] = Json(a.veth_host);
  o["veth_container"] = Json(a.veth_container);
  o["ip_cidr"] = Json(a.ip_cidr);
  o["gateway"] = Json(a.gateway);
  o["bridge"] = Json(a.bridge);
  o["nat_configured"] = Json(a.nat_configured);
  JsonArray published;
  published.reserve(a.published.size());
  for (const PortMapping& p : a.published)
    published.push_back(port_to_json(p));
  o["published"] = Json(std::move(published));
  return Json(std::move(o));
}

NetworkAllocation allocation_from_json(const Json& j) {
  NetworkAllocation a;
  a.veth_host = j["veth_host"].as_string();
  a.veth_container = j["veth_container"].as_string();
  a.ip_cidr = j["ip_cidr"].as_string();
  a.gateway = j["gateway"].as_string();
  a.bridge = j["bridge"].as_string();
  a.nat_configured = j["nat_configured"].as_bool();
  a.published = ports_from_json(j["published"]);
  return a;
}

// Removes <dir> and everything below it. Confined by construction to
// <state_root>/<id>, which only we ever write into. Symlinks are unlinked, not
// followed, so a symlink planted in a container directory cannot be used to
// walk us out of the state root.
bool remove_tree(const std::string& path, int depth) {
  if (depth > 16)
    return false;

  DIR* dir = ::opendir(path.c_str());
  if (dir == nullptr)
    return ::rmdir(path.c_str()) == 0 || errno == ENOENT;

  bool ok = true;
  while (dirent* entry = ::readdir(dir)) {
    std::string name = entry->d_name;
    if (name == "." || name == "..")
      continue;
    std::string child = path + "/" + name;
    struct stat st {};
    if (::lstat(child.c_str(), &st) < 0) {
      ok = false;
      continue;
    }
    if (S_ISDIR(st.st_mode)) {
      ok = remove_tree(child, depth + 1) && ok;
    } else if (::unlink(child.c_str()) < 0 && errno != ENOENT) {
      ok = false;
    }
  }
  ::closedir(dir);

  if (::rmdir(path.c_str()) < 0 && errno != ENOENT)
    ok = false;
  return ok;
}

}  // namespace

// ---------------------------------------------------------------------------
// ContainerState
// ---------------------------------------------------------------------------
Json ContainerState::to_json() const {
  JsonObject o;
  o["id"] = Json(id);
  o["name"] = Json(name);
  o["status"] = Json(container_status_name(status));
  o["pid"] = Json(static_cast<std::int64_t>(pid));
  o["pid_start_time"] = Json(pid_start_time);
  o["created_at"] = Json(created_at);
  o["started_at"] = Json(started_at);
  o["finished_at"] = Json(finished_at);
  o["exit_code"] = Json(exit_code);
  o["term_signal"] = Json(term_signal);
  o["cgroup_path"] = Json(cgroup_path);
  o["network"] = allocation_to_json(network);
  o["config"] = config_to_json(config);
  return Json(std::move(o));
}

Expected<ContainerState> ContainerState::from_json(const Json& j) {
  if (j.type() != Json::Type::Object) {
    return Err(
        Error::invalid(Op::ReadState, "container state is not a JSON object"));
  }
  if (j["id"].type() != Json::Type::String || j["id"].as_string().empty()) {
    return Err(
        Error::invalid(Op::ReadState,
                       "container state has no 'id' field; the file is not a "
                       "MiniContainer state record"));
  }

  ContainerState s;
  s.id = j["id"].as_string();
  s.name = j["name"].as_string();
  s.status = container_status_from_string(j["status"].as_string());
  s.pid = static_cast<::pid_t>(j["pid"].as_int(-1));
  s.pid_start_time = j["pid_start_time"].as_uint();
  s.created_at = j["created_at"].as_string();
  s.started_at = j["started_at"].as_string();
  s.finished_at = j["finished_at"].as_string();
  s.exit_code = static_cast<int>(j["exit_code"].as_int());
  s.term_signal = static_cast<int>(j["term_signal"].as_int());
  s.cgroup_path = j["cgroup_path"].as_string();
  s.network = allocation_from_json(j["network"]);
  s.config = config_from_json(j["config"]);
  return s;
}

// ---------------------------------------------------------------------------
// StateStore
// ---------------------------------------------------------------------------
StateStore::StateStore(RuntimePaths paths) : paths_(std::move(paths)) {}

Expected<void> StateStore::save(const ContainerState& state) {
  if (state.id.empty()) {
    return Err(Error::invalid(Op::WriteState,
                              "refusing to save a container state with no id"));
  }

  MC_CHECK(
      make_directories(paths_.container_dir(state.id), Op::CreateStateDir));

  // A trailing newline so `cat state.json` in a terminal behaves, and dump(2)
  // so a human debugging a stuck container can read the file directly.
  std::string text = state.to_json().dump(2);
  text.push_back('\n');
  return write_file_atomic(paths_.state_path(state.id), text, Op::WriteState);
}

Expected<ContainerState> StateStore::load(const std::string& id) const {
  const std::string path = paths_.state_path(id);

  auto text = read_file(path, Op::ReadState);
  if (!text) {
    return Err(std::move(text).error().with_context("state file " + path));
  }

  auto parsed = json_parse(*text, Op::ReadState);
  if (!parsed) {
    return Err(std::move(parsed).error().with_context("state file " + path));
  }

  auto state = ContainerState::from_json(*parsed);
  if (!state) {
    return Err(std::move(state).error().with_context("state file " + path));
  }
  return state;
}

Expected<std::vector<ContainerState>> StateStore::list() const {
  std::vector<ContainerState> out;

  DIR* dir = ::opendir(paths_.state_root.c_str());
  if (dir == nullptr) {
    // No state root yet simply means no containers have ever been created;
    // `ps` on a fresh host should print an empty table, not an error.
    if (errno == ENOENT)
      return out;
    return Err(
        Error::syscall(Op::ReadState, "opendir", errno, paths_.state_root));
  }

  while (dirent* entry = ::readdir(dir)) {
    std::string name = entry->d_name;
    if (name == "." || name == "..")
      continue;
    if (!is_directory(paths_.container_dir(name)))
      continue;

    // A container whose state.json is missing, truncated, or corrupt is
    // skipped rather than fatal: one bad record must not blind the operator to
    // every other container on the host.
    auto state = load(name);
    if (state)
      out.push_back(std::move(state).value());
  }
  ::closedir(dir);

  return out;
}

Expected<void> StateStore::remove(const std::string& id) {
  if (id.empty()) {
    return Err(Error::invalid(Op::RemoveState, "empty container id"));
  }

  const std::string dir = paths_.container_dir(id);
  if (!path_exists(dir)) {
    return Err(Error::invalid(Op::RemoveState,
                              "no such container state directory: " + dir));
  }
  if (!remove_tree(dir, 0)) {
    return Err(Error::syscall(Op::RemoveState, "rmdir", errno, dir));
  }
  return Ok();
}

Expected<ContainerState> StateStore::resolve(
    const std::string& name_or_id) const {
  if (name_or_id.empty()) {
    return Err(Error::invalid(Op::ReadState, "empty container name or id"));
  }

  // A full id is the cheapest and least ambiguous match, and it is what every
  // script-driven caller passes.
  if (auto exact = load(name_or_id))
    return exact;

  std::vector<ContainerState> all = MC_TRY(list());

  std::vector<ContainerState> by_prefix;
  for (const ContainerState& s : all) {
    if (s.id.size() > name_or_id.size() &&
        s.id.compare(0, name_or_id.size(), name_or_id) == 0) {
      by_prefix.push_back(s);
    }
  }
  if (by_prefix.size() == 1)
    return by_prefix.front();
  if (by_prefix.size() > 1) {
    // Picking one arbitrarily would eventually stop the wrong container, so
    // name the candidates and make the operator disambiguate.
    std::string candidates;
    for (const ContainerState& s : by_prefix) {
      if (!candidates.empty())
        candidates += ", ";
      candidates += s.id;
      if (!s.name.empty())
        candidates += " (" + s.name + ")";
    }
    return Err(Error::invalid(Op::ReadState,
                              "container id prefix '" + name_or_id +
                                  "' is ambiguous; candidates: " + candidates));
  }

  std::vector<ContainerState> by_name;
  for (const ContainerState& s : all) {
    if (!s.name.empty() && s.name == name_or_id)
      by_name.push_back(s);
  }
  if (by_name.size() == 1)
    return by_name.front();
  if (by_name.size() > 1) {
    std::string candidates;
    for (const ContainerState& s : by_name) {
      if (!candidates.empty())
        candidates += ", ";
      candidates += s.id;
    }
    return Err(Error::invalid(
        Op::ReadState, "container name '" + name_or_id +
                           "' matches several containers: " + candidates));
  }

  return Err(Error::invalid(
      Op::ReadState, "no such container: '" + name_or_id +
                         "' (searched full ids, id prefixes, and names under " +
                         paths_.state_root + ")"));
}

bool StateStore::is_alive(const ContainerState& state) const noexcept {
  if (state.pid <= 0)
    return false;

  const std::string proc = "/proc/" + std::to_string(state.pid);
  if (!path_exists(proc))
    return false;

  // The start-time comparison is the whole point of recording it: /proc/<pid>
  // existing only proves that SOME process holds that pid, and the kernel
  // recycles pids. A record whose start time was never captured (0) is
  // therefore treated as not alive rather than trusted.
  std::optional<std::uint64_t> start = read_pid_start_time(state.pid);
  return start.has_value() && *start == state.pid_start_time;
}

Expected<ContainerState> StateStore::refresh(const ContainerState& state) {
  ContainerState updated = state;
  if (updated.status == ContainerStatus::Running && !is_alive(updated)) {
    updated.status = ContainerStatus::Stopped;
    // We did not observe the exit, so we cannot know the exit code; the best
    // we can honestly record is when we noticed.
    if (updated.finished_at.empty())
      updated.finished_at = iso8601_utc_millis();
  }
  // Deliberately not persisted here: the caller decides whether this
  // reconciliation is worth a write, so a read-only `ps` stays read-only.
  return updated;
}

// ---------------------------------------------------------------------------
// read_pid_start_time
// ---------------------------------------------------------------------------
std::optional<std::uint64_t> read_pid_start_time(::pid_t pid) noexcept {
  if (pid <= 0)
    return std::nullopt;

  auto text = read_file("/proc/" + std::to_string(pid) + "/stat", Op::ReadFile);
  if (!text)
    return std::nullopt;
  const std::string& line = *text;

  // Field 2 is comm, in parentheses, and comm may contain both spaces and
  // parentheses ("(sd-pam)", or anything a process chose to prctl itself).
  // The LAST ')' is therefore the only reliable anchor; everything after it is
  // whitespace-separated and safe to tokenise.
  std::size_t close = line.rfind(')');
  if (close == std::string::npos)
    return std::nullopt;

  std::size_t i = close + 1;
  // The token immediately after ')' is field 3 (state), so starttime - field
  // 22 - is the 20th token from here.
  constexpr int kTokensToSkip = 19;
  for (int skipped = 0; skipped < kTokensToSkip; ++skipped) {
    while (i < line.size() && line[i] == ' ')
      ++i;
    if (i >= line.size())
      return std::nullopt;
    while (i < line.size() && line[i] != ' ')
      ++i;
  }
  while (i < line.size() && line[i] == ' ')
    ++i;
  if (i >= line.size())
    return std::nullopt;

  std::size_t end = i;
  while (end < line.size() && line[end] >= '0' && line[end] <= '9')
    ++end;
  if (end == i)
    return std::nullopt;

  std::uint64_t value = 0;
  for (std::size_t k = i; k < end; ++k)
    value = value * 10 + static_cast<std::uint64_t>(line[k] - '0');
  return value;
}

}  // namespace mc
