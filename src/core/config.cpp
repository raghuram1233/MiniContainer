// SPDX-License-Identifier: MIT
//
// MiniContainer - Tier 0 foundation: the container specification.
// Implementation. See include/minicontainer/config.h for the contract.

#include "minicontainer/config.h"

#include <fcntl.h>
#include <unistd.h>

#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <random>

namespace mc {

// ---------------------------------------------------------------------------
// Memory sizes.
// ---------------------------------------------------------------------------
Expected<std::uint64_t> parse_memory_size(std::string_view text) {
  if (text.empty()) {
    return Err(Error::invalid(Op::ParseConfig, "empty memory size"));
  }
  if (text[0] == '-') {
    return Err(Error::invalid(
        Op::ParseConfig, "negative memory size: '" + std::string(text) + "'"));
  }

  std::size_t i = (text[0] == '+') ? 1 : 0;
  std::size_t digits_start = i;
  while (i < text.size() && std::isdigit(static_cast<unsigned char>(text[i]))) {
    ++i;
  }
  if (i == digits_start) {
    return Err(Error::invalid(
        Op::ParseConfig, "not a memory size: '" + std::string(text) + "'"));
  }

  constexpr std::uint64_t kMax = std::numeric_limits<std::uint64_t>::max();
  std::uint64_t value = 0;
  for (std::size_t k = digits_start; k < i; ++k) {
    int d = text[k] - '0';
    if (value > (kMax - static_cast<std::uint64_t>(d)) / 10) {
      return Err(Error::invalid(Op::ParseConfig, "memory size overflow: '" +
                                                     std::string(text) + "'"));
    }
    value = value * 10 + static_cast<std::uint64_t>(d);
  }

  std::string suffix;
  for (std::size_t k = i; k < text.size(); ++k) {
    suffix.push_back(
        static_cast<char>(std::tolower(static_cast<unsigned char>(text[k]))));
  }

  std::uint64_t multiplier = 1;
  if (suffix.empty() || suffix == "b") {
    multiplier = 1;
  } else if (suffix == "k" || suffix == "kb") {
    multiplier = 1024ULL;
  } else if (suffix == "m" || suffix == "mb") {
    multiplier = 1024ULL * 1024ULL;
  } else if (suffix == "g" || suffix == "gb") {
    multiplier = 1024ULL * 1024ULL * 1024ULL;
  } else {
    return Err(Error::invalid(Op::ParseConfig, "unknown memory size suffix: '" +
                                                   std::string(text) + "'"));
  }

  if (multiplier != 1 && value > kMax / multiplier) {
    return Err(Error::invalid(
        Op::ParseConfig, "memory size overflow: '" + std::string(text) + "'"));
  }

  return value * multiplier;
}

std::string format_memory_size(std::uint64_t bytes) {
  constexpr std::uint64_t kKB = 1024ULL;
  constexpr std::uint64_t kMB = kKB * 1024ULL;
  constexpr std::uint64_t kGB = kMB * 1024ULL;

  char buf[64];
  if (bytes < kKB) {
    std::snprintf(buf, sizeof(buf), "%lluB",
                  static_cast<unsigned long long>(bytes));
  } else if (bytes < kMB) {
    std::snprintf(buf, sizeof(buf), "%.1fKB",
                  static_cast<double>(bytes) / static_cast<double>(kKB));
  } else if (bytes < kGB) {
    std::snprintf(buf, sizeof(buf), "%.1fMB",
                  static_cast<double>(bytes) / static_cast<double>(kMB));
  } else {
    std::snprintf(buf, sizeof(buf), "%.1fGB",
                  static_cast<double>(bytes) / static_cast<double>(kGB));
  }
  return std::string(buf);
}

std::optional<std::string> Resources::cpu_max_value() const {
  if (!cpus.has_value())
    return std::nullopt;
  double c = *cpus;
  if (c <= 0.0)
    return std::nullopt;  // invalid values are rejected by validate()

  std::uint64_t period = kDefaultCpuPeriodUs;
  std::uint64_t quota =
      static_cast<std::uint64_t>(c * static_cast<double>(period) + 0.5);
  return std::to_string(quota) + " " + std::to_string(period);
}

// ---------------------------------------------------------------------------
// Networking.
// ---------------------------------------------------------------------------
NetworkMode network_mode_from_string(std::string_view s) {
  std::string lower;
  lower.reserve(s.size());
  for (char c : s) {
    lower.push_back(
        static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
  }
  if (lower == "bridge")
    return NetworkMode::Bridge;
  if (lower == "host")
    return NetworkMode::Host;
  return NetworkMode::None;
}

const char* network_mode_name(NetworkMode m) noexcept {
  switch (m) {
    case NetworkMode::None:
      return "none";
    case NetworkMode::Bridge:
      return "bridge";
    case NetworkMode::Host:
      return "host";
  }
  return "none";
}

namespace {
Expected<std::uint16_t> parse_port_number(std::string_view s,
                                          std::string_view original) {
  if (s.empty()) {
    return Err(Error::invalid(
        Op::ParseConfig,
        "empty port in mapping: '" + std::string(original) + "'"));
  }
  if (s.size() > 5) {
    return Err(Error::invalid(
        Op::ParseConfig,
        "port out of range (1-65535): '" + std::string(original) + "'"));
  }
  for (char c : s) {
    if (!std::isdigit(static_cast<unsigned char>(c))) {
      return Err(Error::invalid(
          Op::ParseConfig,
          "non-numeric port in mapping: '" + std::string(original) + "'"));
    }
  }
  long v = std::strtol(std::string(s).c_str(), nullptr, 10);
  if (v < 1 || v > 65535) {
    return Err(Error::invalid(
        Op::ParseConfig,
        "port out of range (1-65535): '" + std::string(original) + "'"));
  }
  return static_cast<std::uint16_t>(v);
}
}  // namespace

Expected<PortMapping> parse_port_mapping(std::string_view text) {
  auto slash = text.find('/');
  std::string_view main_part =
      (slash == std::string_view::npos) ? text : text.substr(0, slash);

  std::string proto = "tcp";
  if (slash != std::string_view::npos) {
    proto = std::string(text.substr(slash + 1));
    for (char& c : proto) {
      c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }
  }
  if (proto != "tcp" && proto != "udp") {
    return Err(Error::invalid(
        Op::ParseConfig,
        "invalid protocol (expected tcp or udp): '" + std::string(text) + "'"));
  }

  auto colon = main_part.find(':');
  if (colon == std::string_view::npos) {
    return Err(Error::invalid(
        Op::ParseConfig,
        "invalid port mapping (expected host:container[/proto]): '" +
            std::string(text) + "'"));
  }

  std::uint16_t host_port =
      MC_TRY(parse_port_number(main_part.substr(0, colon), text));
  std::uint16_t container_port =
      MC_TRY(parse_port_number(main_part.substr(colon + 1), text));

  PortMapping pm;
  pm.host_port = host_port;
  pm.container_port = container_port;
  pm.protocol = proto;
  return pm;
}

// ---------------------------------------------------------------------------
// Names and ids.
// ---------------------------------------------------------------------------
std::string generate_container_id() {
  unsigned char buf[6];
  bool got = false;

  int fd = ::open("/dev/urandom", O_RDONLY | O_CLOEXEC);
  if (fd >= 0) {
    ssize_t n = ::read(fd, buf, sizeof(buf));
    ::close(fd);
    got = (n == static_cast<ssize_t>(sizeof(buf)));
  }

  if (!got) {
    std::random_device rd;
    std::uint64_t bits = (static_cast<std::uint64_t>(rd()) << 32) | rd();
    for (std::size_t i = 0; i < sizeof(buf); ++i) {
      buf[i] = static_cast<unsigned char>((bits >> (i * 8)) & 0xFF);
    }
  }

  static const char kHex[] = "0123456789abcdef";
  std::string id;
  id.reserve(12);
  for (unsigned char b : buf) {
    id.push_back(kHex[(b >> 4) & 0xF]);
    id.push_back(kHex[b & 0xF]);
  }
  return id;
}

bool is_valid_container_name(std::string_view name) noexcept {
  if (name.empty() || name.size() > 63)
    return false;
  if (!std::isalnum(static_cast<unsigned char>(name[0])))
    return false;
  for (std::size_t i = 1; i < name.size(); ++i) {
    char c = name[i];
    if (!(std::isalnum(static_cast<unsigned char>(c)) || c == '_' || c == '.' ||
          c == '-')) {
      return false;
    }
  }
  return true;
}

bool is_valid_hostname(std::string_view host) noexcept {
  if (host.empty() || host.size() > 63)
    return false;

  std::size_t start = 0;
  while (start <= host.size()) {
    auto dot = host.find('.', start);
    std::size_t end = (dot == std::string_view::npos) ? host.size() : dot;
    std::string_view label = host.substr(start, end - start);

    if (label.empty() || label.size() > 63)
      return false;
    if (label.front() == '-' || label.back() == '-')
      return false;
    for (char c : label) {
      if (!(std::isalnum(static_cast<unsigned char>(c)) || c == '-')) {
        return false;
      }
    }

    if (dot == std::string_view::npos)
      break;
    start = dot + 1;
  }
  return true;
}

// ---------------------------------------------------------------------------
// ContainerConfig.
// ---------------------------------------------------------------------------
namespace {
bool is_plausible_cap_name(const std::string& name) {
  if (name == "ALL")
    return true;

  std::string rest = name;
  static constexpr std::string_view kPrefix = "CAP_";
  if (rest.size() > kPrefix.size() &&
      rest.compare(0, kPrefix.size(), kPrefix) == 0) {
    rest = rest.substr(kPrefix.size());
  }
  if (rest.empty())
    return false;

  for (char c : rest) {
    if (!(std::isupper(static_cast<unsigned char>(c)) ||
          std::isdigit(static_cast<unsigned char>(c)) || c == '_')) {
      return false;
    }
  }
  return true;
}
}  // namespace

Expected<void> ContainerConfig::validate() const {
  if (!name.empty() && !is_valid_container_name(name)) {
    return Err(Error::invalid(Op::ValidateConfig,
                              "invalid container name: '" + name + "'"));
  }
  if (!hostname.empty() && !is_valid_hostname(hostname)) {
    return Err(Error::invalid(Op::ValidateConfig,
                              "invalid hostname: '" + hostname + "'"));
  }
  if (args.empty()) {
    return Err(Error::invalid(Op::ValidateConfig, "args must not be empty"));
  }
  if (args[0].empty()) {
    return Err(Error::invalid(Op::ValidateConfig,
                              "args[0] (the entrypoint) must not be empty"));
  }
  if (resources.memory_bytes.has_value() && *resources.memory_bytes < 4096) {
    return Err(Error::invalid(Op::ValidateConfig,
                              "memory must be >= 4096 bytes, got " +
                                  std::to_string(*resources.memory_bytes)));
  }
  if (resources.cpus.has_value() && *resources.cpus <= 0.0) {
    return Err(Error::invalid(
        Op::ValidateConfig,
        "cpus must be > 0, got " + std::to_string(*resources.cpus)));
  }
  if (resources.pids_max.has_value() && *resources.pids_max < 1) {
    return Err(Error::invalid(Op::ValidateConfig, "pids_max must be >= 1"));
  }
  for (const auto& e : env) {
    if (e.find('=') == std::string::npos) {
      return Err(Error::invalid(Op::ValidateConfig,
                                "env entry missing '=': '" + e + "'"));
    }
  }
  for (const auto& pm : network.ports) {
    if (pm.host_port < 1 || pm.container_port < 1) {
      return Err(Error::invalid(Op::ValidateConfig,
                                "port mapping has an out-of-range port"));
    }
    if (pm.protocol != "tcp" && pm.protocol != "udp") {
      return Err(Error::invalid(
          Op::ValidateConfig,
          "port mapping has invalid protocol: '" + pm.protocol + "'"));
    }
  }
  for (const auto& c : security.cap_drop) {
    if (!is_plausible_cap_name(c)) {
      return Err(
          Error::invalid(Op::ValidateConfig,
                         "invalid capability name in cap_drop: '" + c + "'"));
    }
  }
  for (const auto& c : security.cap_add) {
    if (!is_plausible_cap_name(c)) {
      return Err(
          Error::invalid(Op::ValidateConfig,
                         "invalid capability name in cap_add: '" + c + "'"));
    }
  }
  if (security.userns_size < 1) {
    return Err(Error::invalid(Op::ValidateConfig, "userns_size must be >= 1"));
  }
  if (security.seccomp == SeccompMode::Profile &&
      security.seccomp_profile_path.empty()) {
    return Err(Error::invalid(
        Op::ValidateConfig,
        "seccomp profile mode requires a non-empty seccomp_profile_path"));
  }
  // cpu.weight only accepts 1..10000. Without this check a Docker habit like
  // --cpu-shares 262144 reaches the kernel and fails as a bare EINVAL on a
  // cgroup file, with nothing to say what the valid range was.
  if (resources.cpu_shares.has_value() &&
      (*resources.cpu_shares < 1 || *resources.cpu_shares > 10000)) {
    return Err(Error::invalid(
        Op::ValidateConfig,
        "--cpu-shares must be between 1 and 10000 (got " +
            std::to_string(*resources.cpu_shares) +
            "); it maps to cgroup v2's cpu.weight, which has that range"));
  }

  return Ok();
}

void ContainerConfig::apply_defaults() {
  if (id.empty())
    id = generate_container_id();
  if (hostname.empty())
    hostname = id;
  if (name.empty())
    name = id;
  if (working_dir.empty())
    working_dir = "/";
}

// ---------------------------------------------------------------------------
// RuntimePaths.
// ---------------------------------------------------------------------------
std::string RuntimePaths::container_dir(std::string_view id) const {
  return state_root + "/" + std::string(id);
}
std::string RuntimePaths::config_path(std::string_view id) const {
  return container_dir(id) + "/config.json";
}
std::string RuntimePaths::state_path(std::string_view id) const {
  return container_dir(id) + "/state.json";
}
std::string RuntimePaths::pid_path(std::string_view id) const {
  return container_dir(id) + "/pid";
}
std::string RuntimePaths::log_dir(std::string_view id) const {
  return container_dir(id) + "/logs";
}

RuntimePaths RuntimePaths::from_env() {
  RuntimePaths p;
  if (const char* root = std::getenv("MINICONTAINER_ROOT");
      root != nullptr && root[0] != '\0') {
    p.state_root = root;
  }
  if (const char* cg = std::getenv("MINICONTAINER_CGROUP_ROOT");
      cg != nullptr && cg[0] != '\0') {
    p.cgroup_root = cg;
  }
  return p;
}

}  // namespace mc
