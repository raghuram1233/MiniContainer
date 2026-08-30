// SPDX-License-Identifier: MIT
//
// MiniContainer - Tier 0 foundation: the container specification.
//
// ContainerConfig is the single description of "what container do you want".
// The CLI produces one; the OCI-style bundle parser produces one; the state
// store round-trips one. Nothing downstream of this struct ever looks at argv
// or at config.json again - that is what keeps parsing independent of runtime
// logic.
//
// validate() is a PURE function: no syscalls, no filesystem access. That makes
// the whole of configuration validation unit-testable without root and without
// namespaces, which is where most of the test suite lives.
// Filesystem-dependent checks (does the rootfs exist, does it contain the
// entrypoint) belong to Runtime::preflight(), not here.
#pragma once

#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <vector>

#include "minicontainer/errors.h"

namespace mc {

// ---------------------------------------------------------------------------
// Resource limits. std::nullopt means "do not set this limit at all", which is
// different from "set it to the maximum" - we never write a cgroup file we were
// not asked to write.
// ---------------------------------------------------------------------------
struct Resources {
  std::optional<std::uint64_t> memory_bytes;       // memory.max
  std::optional<std::uint64_t> memory_swap_bytes;  // memory.swap.max
  std::optional<double> cpus;                      // -> cpu.max "quota period"
  std::optional<std::uint64_t> cpu_shares;         // cpu.weight
  std::optional<std::uint64_t> pids_max;           // pids.max
  std::optional<std::string> cpuset_cpus;          // cpuset.cpus

  // cpu.max is written as "<quota> <period>" in microseconds.
  // cpus=0.5 with the default 100000us period yields "50000 100000".
  static constexpr std::uint64_t kDefaultCpuPeriodUs = 100000;
  [[nodiscard]] std::optional<std::string> cpu_max_value() const;
};

// Parses "256M", "1G", "512k", "1048576". Case-insensitive suffix,
// 1024-based. Rejects negatives, empty strings, and overflow.
Expected<std::uint64_t> parse_memory_size(std::string_view text);

// Renders 268435456 as "256.0MB" for `stats` and `inspect`.
std::string format_memory_size(std::uint64_t bytes);

// ---------------------------------------------------------------------------
// Networking
// ---------------------------------------------------------------------------
enum class NetworkMode {
  None,    // netns with only loopback up
  Bridge,  // veth pair into a managed bridge
  Host,    // no CLONE_NEWNET at all
};

NetworkMode network_mode_from_string(std::string_view s);
const char* network_mode_name(NetworkMode m) noexcept;

struct PortMapping {
  std::uint16_t host_port = 0;
  std::uint16_t container_port = 0;
  std::string protocol = "tcp";  // "tcp" | "udp"
};

// Parses "8080:80" or "8080:80/udp".
Expected<PortMapping> parse_port_mapping(std::string_view text);

struct NetworkConfig {
  NetworkMode mode = NetworkMode::None;
  std::string bridge_name = "mc-br0";
  std::string subnet_cidr = "10.88.0.0/16";
  std::string gateway_ip = "10.88.0.1";
  std::optional<std::string> container_ip;  // auto-allocated when empty
  std::vector<std::string> dns_servers{"1.1.1.1", "8.8.8.8"};
  std::vector<PortMapping> ports;
  bool enable_nat = true;
};

// ---------------------------------------------------------------------------
// Security
// ---------------------------------------------------------------------------
enum class SeccompMode {
  Off,      // no filter installed
  Default,  // built-in deny-list profile
  Profile,  // load from seccomp_profile_path
};

struct SecurityConfig {
  // Applied in order: start from the default set, drop cap_drop, then add
  // cap_add. "ALL" is accepted in either list.
  std::vector<std::string> cap_drop;
  std::vector<std::string> cap_add;

  SeccompMode seccomp = SeccompMode::Default;
  std::string seccomp_profile_path;

  // no_new_privs is on by default and cannot be silently disabled; turning it
  // off requires an explicit --no-new-privs=false and is warned about, because
  // seccomp(2) requires it once CAP_SYS_ADMIN is gone.
  bool no_new_privs = true;

  // Opt-in user namespace. Off by default: enabling it costs mknod, binding
  // privileged ports, and devpts gid=5. See security.h for the ordering
  // rules that make this safe.
  bool userns = false;
  std::uint32_t userns_host_uid = 0;  // host uid that maps to container uid 0
  std::uint32_t userns_host_gid = 0;
  std::uint32_t userns_size = 65536;

  bool privileged = false;  // keeps all caps; must be explicit and is warned
  bool readonly_rootfs = false;
};

// ---------------------------------------------------------------------------
// The container specification
// ---------------------------------------------------------------------------
struct ContainerConfig {
  std::string id;        // generated; 12 hex chars
  std::string name;      // user-facing, unique among live containers
  std::string hostname;  // UTS namespace; defaults to id when empty

  std::string rootfs_path;
  std::vector<std::string>
      args;  // argv for the entrypoint; args[0] is the binary
  std::vector<std::string> env;  // "KEY=VALUE"
  std::string working_dir = "/";

  Resources resources;
  NetworkConfig network;
  SecurityConfig security;

  // Extra bind mounts, "src:dst" or "src:dst:ro".
  std::vector<std::string> bind_mounts;

  bool tty = false;
  bool detach = false;
  bool remove_on_exit = false;

  // Pure validation: no syscalls, no filesystem access. Checks name/hostname
  // charset and length, that args is non-empty, that limits are in range, that
  // capability names are known, and that IP/CIDR strings parse.
  [[nodiscard]] Expected<void> validate() const;

  // Applies defaults that depend on other fields (hostname <- id, and so on).
  void apply_defaults();
};

// 12 hex characters from a CSPRNG. Collision-checked against the state store by
// the caller.
std::string generate_container_id();

// Names must be usable in a path, an interface name, and a cgroup directory:
// [a-zA-Z0-9][a-zA-Z0-9_.-]{0,62}
bool is_valid_container_name(std::string_view name) noexcept;

// RFC 1123 label rules, max 63 chars.
bool is_valid_hostname(std::string_view host) noexcept;

// ---------------------------------------------------------------------------
// Runtime-wide paths. Everything MiniContainer creates lives under these roots,
// which is what makes cleanup safe: we never touch a cgroup, mount, or
// interface outside them.
// ---------------------------------------------------------------------------
struct RuntimePaths {
  std::string state_root = "/var/lib/minicontainer";
  std::string cgroup_root = "/sys/fs/cgroup";
  std::string cgroup_scope = "minicontainer";  // <cgroup_root>/<scope>/<id>

  [[nodiscard]] std::string container_dir(std::string_view id) const;
  [[nodiscard]] std::string config_path(std::string_view id) const;
  [[nodiscard]] std::string state_path(std::string_view id) const;
  [[nodiscard]] std::string pid_path(std::string_view id) const;
  [[nodiscard]] std::string log_dir(std::string_view id) const;

  // Reads MINICONTAINER_ROOT / MINICONTAINER_CGROUP_ROOT so integration tests
  // can redirect every write into a scratch directory.
  static RuntimePaths from_env();
};

}  // namespace mc
