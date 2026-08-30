// SPDX-License-Identifier: MIT
//
// MiniContainer - Tier 2 networking: the host bridge, plus the shared plumbing
// the rest of src/network/ is built on. See include/minicontainer/network.h for
// the contract and the two design traps (post-clone ordering, WSL2 double NAT).
//
// WHY WE SHELL OUT AT ALL
// -----------------------
// Creating a bridge, a veth pair, or an iptables rule from C++ means speaking
// rtnetlink and libxtables directly. That is a large amount of protocol code
// whose only payoff is avoiding two well-known binaries that every Linux host
// with containers already has. docs/networking.md describes the operations in
// terms of `ip` and `iptables`, and this module implements exactly that, so
// what the code does and what the docs teach cannot drift apart.
//
// WHY NEVER system()
// ------------------
// A container name, a bridge name and an interface name all reach these
// commands, and all three originate in user input. `system("ip link add " +
// name)` turns `--name 'x; rm -rf /'` into a root shell command. Every command
// here therefore goes through run_command(), which is fork + execvp with an
// argv ARRAY: there is no shell anywhere in the pipeline, so quoting, $(), and
// ; simply have no meaning. validate_ifname() closes the remaining gap, which
// is not injection but option injection - execvp is perfectly happy to pass a
// name beginning with '-' to `ip`, which will read it as a flag.
//
// BETWEEN fork() AND execvp()
// ---------------------------
// The forked half of run_command() lives under the same rule as the post-clone
// child described in errors.h: only async-signal-safe calls. That is why the
// char* argv array is built before the fork, not after it.
//
// SHARED PLUMBING LIVES HERE
// --------------------------
// run_command(), the IPv4/CIDR parsers, the interface-name validator and the
// WSL probe are used by veth.cpp and nat.cpp too. They are declared - not
// defined - at the top of those files in a block identical to the one below,
// because this module is deliberately four .cpp files with no private header
// of its own.

#include <sys/wait.h>

#include <fcntl.h>
#include <poll.h>
#include <unistd.h>

#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "minicontainer/errors.h"
#include "minicontainer/logging.h"
#include "minicontainer/network.h"
#include "minicontainer/syscall.h"

namespace mc {
namespace net_detail {

// ---------------------------------------------------------------------------
// The shared surface. Repeated verbatim in veth.cpp, nat.cpp and the tests.
// ---------------------------------------------------------------------------
struct CommandResult {
  int exit_code = -1;  // -1 when the process died on a signal
  std::string out;
  std::string err;
};

Expected<CommandResult> run_command(const std::vector<std::string>& argv);
Expected<void> run_checked(Op op, const std::vector<std::string>& argv);
Expected<bool> run_succeeds(const std::vector<std::string>& argv);
std::string join_command(const std::vector<std::string>& argv);

struct Ipv4Cidr {
  std::uint32_t network = 0;  // host byte order, host bits already cleared
  int prefix = 0;             // 0..32
};

Expected<std::uint32_t> parse_ipv4(std::string_view text, Op op);
Expected<Ipv4Cidr> parse_ipv4_cidr(std::string_view text, Op op);
std::string format_ipv4(std::uint32_t addr);
std::string format_cidr(const Ipv4Cidr& cidr);
Expected<void> validate_ifname(std::string_view name, Op op);
bool osrelease_indicates_wsl(std::string_view osrelease) noexcept;
bool running_under_wsl() noexcept;

// ---------------------------------------------------------------------------
// Command execution.
// ---------------------------------------------------------------------------
namespace {

// A misbehaving child could otherwise stream until the parent is OOM-killed.
// Nothing this module runs produces more than a few hundred bytes.
constexpr std::size_t kMaxCapture = 64 * 1024;

std::string_view trim(std::string_view s) {
  std::size_t b = 0;
  std::size_t e = s.size();
  while (b < e && (s[b] == ' ' || s[b] == '\t' || s[b] == '\n' || s[b] == '\r'))
    ++b;
  while (e > b && (s[e - 1] == ' ' || s[e - 1] == '\t' || s[e - 1] == '\n' ||
                   s[e - 1] == '\r'))
    --e;
  return s.substr(b, e - b);
}

// Turns a captured exit status plus stderr into the detail string that makes
// an error actionable. "iptables failed" is useless; "iptables -t nat -A ...
// exited 2: iptables: No chain/target/match by that name" is not.
std::string failure_detail(const std::vector<std::string>& argv,
                           const CommandResult& r) {
  std::string detail = join_command(argv);
  if (r.exit_code < 0) {
    detail += " was killed by a signal";
  } else {
    detail += " exited " + std::to_string(r.exit_code);
  }
  std::string_view msg = trim(r.err);
  if (msg.empty())
    msg = trim(r.out);
  if (!msg.empty()) {
    detail += ": ";
    detail.append(msg);
  }
  if (r.exit_code == 127) {
    detail += " (exit 127 usually means the binary is not on PATH; ";
    detail += "install iproute2 / iptables)";
  }
  return detail;
}

}  // namespace

std::string join_command(const std::vector<std::string>& argv) {
  std::string out;
  for (const std::string& a : argv) {
    if (!out.empty())
      out += ' ';
    out += a;
  }
  return out;
}

Expected<CommandResult> run_command(const std::vector<std::string>& argv) {
  if (argv.empty()) {
    return Err(Error::invalid(Op::Internal, "run_command: empty argv"));
  }

  int out_fds[2] = {-1, -1};
  int err_fds[2] = {-1, -1};
  if (::pipe2(out_fds, O_CLOEXEC) < 0) {
    return Err(
        Error::syscall(Op::CreatePipe, "pipe2", errno, "stdout of " + argv[0]));
  }
  if (::pipe2(err_fds, O_CLOEXEC) < 0) {
    int saved = errno;
    ::close(out_fds[0]);
    ::close(out_fds[1]);
    return Err(
        Error::syscall(Op::CreatePipe, "pipe2", saved, "stderr of " + argv[0]));
  }

  // Built BEFORE fork(). c_str() cannot allocate on an existing std::string,
  // but assembling the vector can, and after fork() allocating is forbidden.
  std::vector<char*> cargv;
  cargv.reserve(argv.size() + 1);
  for (const std::string& a : argv) {
    cargv.push_back(const_cast<char*>(a.c_str()));
  }
  cargv.push_back(nullptr);

  ::pid_t pid = ::fork();
  if (pid < 0) {
    int saved = errno;
    ::close(out_fds[0]);
    ::close(out_fds[1]);
    ::close(err_fds[0]);
    ::close(err_fds[1]);
    return Err(Error::syscall(Op::Internal, "fork", saved, argv[0]));
  }

  if (pid == 0) {
    // Async-signal-safe only from here to execvp(). dup2() clears O_CLOEXEC on
    // the copy, which is what keeps the pipe alive across the exec.
    ::dup2(out_fds[1], STDOUT_FILENO);
    ::dup2(err_fds[1], STDERR_FILENO);
    int devnull = ::open("/dev/null", O_RDONLY);
    if (devnull >= 0) {
      ::dup2(devnull, STDIN_FILENO);
    }
    ::execvp(cargv[0], cargv.data());
    _exit(127);  // conventional "command not found"
  }

  ::close(out_fds[1]);
  ::close(err_fds[1]);

  // Both pipes must be drained concurrently. Reading stdout to EOF first would
  // deadlock the moment a command filled the stderr pipe buffer.
  CommandResult result;
  struct ::pollfd pfds[2];
  pfds[0].fd = out_fds[0];
  pfds[1].fd = err_fds[0];
  pfds[0].events = pfds[1].events = POLLIN;
  std::string* sinks[2] = {&result.out, &result.err};

  int open_fds = 2;
  while (open_fds > 0) {
    pfds[0].revents = pfds[1].revents = 0;
    if (::poll(pfds, 2, -1) < 0) {
      if (errno == EINTR)
        continue;
      break;
    }
    for (int i = 0; i < 2; ++i) {
      if (pfds[i].fd < 0 || pfds[i].revents == 0)
        continue;
      char buf[4096];
      ssize_t n = ::read(pfds[i].fd, buf, sizeof(buf));
      if (n > 0) {
        if (sinks[i]->size() < kMaxCapture) {
          sinks[i]->append(buf, static_cast<std::size_t>(n));
        }
        continue;
      }
      if (n < 0 && errno == EINTR)
        continue;
      ::close(pfds[i].fd);
      pfds[i].fd = -1;
      --open_fds;
    }
  }
  for (int i = 0; i < 2; ++i) {
    if (pfds[i].fd >= 0)
      ::close(pfds[i].fd);
  }

  int wstatus = 0;
  while (::waitpid(pid, &wstatus, 0) < 0) {
    if (errno != EINTR) {
      return Err(Error::syscall(Op::WaitChild, "waitpid", errno, argv[0]));
    }
  }
  result.exit_code = WIFEXITED(wstatus) ? WEXITSTATUS(wstatus) : -1;

  MC_LOG_TRACE("net: " << join_command(argv) << " -> " << result.exit_code);
  return result;
}

Expected<void> run_checked(Op op, const std::vector<std::string>& argv) {
  CommandResult r = MC_TRY(run_command(argv));
  if (r.exit_code != 0) {
    return Err(Error::invalid(op, failure_detail(argv, r)));
  }
  return Ok();
}

Expected<bool> run_succeeds(const std::vector<std::string>& argv) {
  CommandResult r = MC_TRY(run_command(argv));
  return r.exit_code == 0;
}

// ---------------------------------------------------------------------------
// IPv4 / CIDR parsing.
//
// Hand-rolled rather than inet_aton()/inet_pton(): inet_aton accepts "10.88",
// "0x0a580001" and treats a leading zero as OCTAL, so "10.088.0.1" silently
// becomes a different address. A container runtime that quietly hands out the
// wrong address is worse than one that refuses a typo, and this parser is also
// the thing the unit tests can pin down exactly.
// ---------------------------------------------------------------------------
namespace {

// Parses one decimal octet or prefix length. Digits only, no sign, no space.
bool parse_decimal(std::string_view text, unsigned max, unsigned& out) {
  if (text.empty() || text.size() > 3)
    return false;
  unsigned value = 0;
  for (char c : text) {
    if (c < '0' || c > '9')
      return false;
    value = value * 10 + static_cast<unsigned>(c - '0');
  }
  if (value > max)
    return false;
  out = value;
  return true;
}

}  // namespace

Expected<std::uint32_t> parse_ipv4(std::string_view text, Op op) {
  std::uint32_t addr = 0;
  std::size_t start = 0;
  for (int octet = 0; octet < 4; ++octet) {
    std::size_t dot = text.find('.', start);
    bool last = (octet == 3);
    if (last != (dot == std::string_view::npos)) {
      return Err(Error::invalid(
          op, "not a dotted-quad IPv4 address: '" + std::string(text) + "'"));
    }
    std::size_t end = last ? text.size() : dot;
    unsigned value = 0;
    if (!parse_decimal(text.substr(start, end - start), 255, value)) {
      return Err(Error::invalid(
          op, "not a dotted-quad IPv4 address: '" + std::string(text) + "'"));
    }
    addr = (addr << 8) | value;
    start = end + 1;
  }
  return addr;
}

Expected<Ipv4Cidr> parse_ipv4_cidr(std::string_view text, Op op) {
  std::size_t slash = text.find('/');
  if (slash == std::string_view::npos) {
    return Err(Error::invalid(
        op, "missing /prefix in CIDR: '" + std::string(text) + "'"));
  }
  std::uint32_t addr = MC_TRY(parse_ipv4(text.substr(0, slash), op));

  unsigned prefix = 0;
  if (!parse_decimal(text.substr(slash + 1), 32, prefix)) {
    return Err(Error::invalid(
        op, "prefix length must be 0-32: '" + std::string(text) + "'"));
  }

  Ipv4Cidr cidr;
  cidr.prefix = static_cast<int>(prefix);
  // Shifting a 32-bit value by 32 is undefined, so /0 is special-cased.
  std::uint32_t mask = (prefix == 0) ? 0u : (0xFFFFFFFFu << (32 - prefix));
  cidr.network = addr & mask;
  return cidr;
}

std::string format_ipv4(std::uint32_t addr) {
  return std::to_string((addr >> 24) & 0xFF) + "." +
         std::to_string((addr >> 16) & 0xFF) + "." +
         std::to_string((addr >> 8) & 0xFF) + "." + std::to_string(addr & 0xFF);
}

std::string format_cidr(const Ipv4Cidr& cidr) {
  return format_ipv4(cidr.network) + "/" + std::to_string(cidr.prefix);
}

// ---------------------------------------------------------------------------
// Interface names.
//
// execvp() removes shell injection, but not OPTION injection: `ip link add
// -foo type bridge` reads -foo as a flag. The kernel's own limit is
// IFNAMSIZ-1 = 15 bytes, and '/' and whitespace are rejected by the kernel
// anyway - we reject them here so the error names the real problem.
// ---------------------------------------------------------------------------
Expected<void> validate_ifname(std::string_view name, Op op) {
  if (name.empty()) {
    return Err(Error::invalid(op, "empty interface name"));
  }
  if (name.size() > 15) {
    return Err(Error::invalid(op, "interface name '" + std::string(name) +
                                      "' exceeds the kernel's 15-byte limit"));
  }
  if (name == "." || name == "..") {
    return Err(Error::invalid(
        op, "interface name '" + std::string(name) + "' is reserved"));
  }
  for (char c : name) {
    bool ok = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
              (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.';
    if (!ok) {
      return Err(Error::invalid(op, "interface name '" + std::string(name) +
                                        "' contains an illegal character"));
    }
  }
  if (name[0] == '-') {
    return Err(Error::invalid(
        op, "interface name '" + std::string(name) +
                "' starts with '-' and would be parsed as a command option"));
  }
  return Ok();
}

// ---------------------------------------------------------------------------
// WSL detection.
//
// Split into a pure predicate over the osrelease string and a thin reader, so
// the interesting half is unit-testable without a WSL kernel: "5.15.167.4-
// microsoft-standard-WSL2" must match, a stock "6.8.0-45-generic" must not.
// The kernel spelling has been both "Microsoft" (WSL1) and "microsoft" (WSL2),
// hence the case-insensitive compare.
// ---------------------------------------------------------------------------
bool osrelease_indicates_wsl(std::string_view osrelease) noexcept {
  constexpr std::string_view kNeedle = "microsoft";
  if (osrelease.size() < kNeedle.size())
    return false;
  for (std::size_t i = 0; i + kNeedle.size() <= osrelease.size(); ++i) {
    bool match = true;
    for (std::size_t j = 0; j < kNeedle.size(); ++j) {
      char c = osrelease[i + j];
      if (c >= 'A' && c <= 'Z')
        c = static_cast<char>(c - 'A' + 'a');
      if (c != kNeedle[j]) {
        match = false;
        break;
      }
    }
    if (match)
      return true;
  }
  return false;
}

bool running_under_wsl() noexcept {
  static const bool kIsWsl = [] {
    Expected<std::string> release =
        read_file("/proc/sys/kernel/osrelease", Op::ReadFile);
    if (!release)
      return false;
    return osrelease_indicates_wsl(*release);
  }();
  return kIsWsl;
}

}  // namespace net_detail

// The public entry points below are written against the module's internal
// helpers by their short names. net_detail exists to keep those helpers out of
// mc's public surface, not to make every call site verbose.
using net_detail::CommandResult;
using net_detail::parse_ipv4_cidr;
using net_detail::run_checked;
using net_detail::run_command;
using net_detail::run_succeeds;
using net_detail::validate_ifname;

// ---------------------------------------------------------------------------
// ensure_bridge
//
// Idempotent because it has to be: every container start calls it, and the
// bridge is shared host state that outlives any single container. "Already
// correct" is the common case, not the exception.
// ---------------------------------------------------------------------------
Expected<void> ensure_bridge(const NetworkConfig& net) {
  MC_CHECK(net_detail::validate_ifname(net.bridge_name, Op::CreateBridge));
  net_detail::Ipv4Cidr subnet =
      MC_TRY(net_detail::parse_ipv4_cidr(net.subnet_cidr, Op::CreateBridge));
  std::uint32_t gateway =
      MC_TRY(net_detail::parse_ipv4(net.gateway_ip, Op::CreateBridge));

  // A gateway outside the subnet the containers get would produce a bridge
  // that looks configured and routes nothing - catch it here, not in tcpdump.
  std::uint32_t mask =
      (subnet.prefix == 0) ? 0u : (0xFFFFFFFFu << (32 - subnet.prefix));
  if ((gateway & mask) != subnet.network) {
    return Err(Error::invalid(
        Op::CreateBridge,
        "gateway " + net.gateway_ip + " is not inside " + format_cidr(subnet)));
  }

  const std::string gateway_cidr =
      net.gateway_ip + "/" + std::to_string(subnet.prefix);

  bool exists =
      MC_TRY(run_succeeds({"ip", "link", "show", "dev", net.bridge_name}));
  if (!exists) {
    MC_CHECK(
        run_checked(Op::CreateBridge,
                    {"ip", "link", "add", net.bridge_name, "type", "bridge"}));
    MC_LOG_INFO("net: created bridge " << net.bridge_name);
  }

  // Ask the kernel what addresses the bridge already carries rather than
  // adding blindly: `ip addr add` on a duplicate exits 2, and we would have to
  // string-match its stderr to tell "already fine" from "actually broken".
  CommandResult addrs = MC_TRY(
      run_command({"ip", "-4", "-o", "addr", "show", "dev", net.bridge_name}));
  if (addrs.exit_code != 0) {
    return Err(Error::invalid(
        Op::CreateBridge,
        "cannot read addresses of " + net.bridge_name + ": " + addrs.err));
  }
  if (addrs.out.find(" " + gateway_cidr + " ") == std::string::npos) {
    MC_CHECK(run_checked(Op::CreateBridge, {"ip", "addr", "add", gateway_cidr,
                                            "dev", net.bridge_name}));
    MC_LOG_INFO("net: assigned " << gateway_cidr << " to " << net.bridge_name);
  }

  // `ip link set up` on an already-up link is a no-op, so this needs no probe.
  MC_CHECK(run_checked(Op::CreateBridge,
                       {"ip", "link", "set", net.bridge_name, "up"}));
  return Ok();
}

// ---------------------------------------------------------------------------
// attach_to_bridge
// ---------------------------------------------------------------------------
Expected<void> attach_to_bridge(const NetworkAllocation& alloc) {
  using namespace net_detail;

  MC_CHECK(validate_ifname(alloc.veth_host, Op::AttachToBridge));
  MC_CHECK(validate_ifname(alloc.bridge, Op::AttachToBridge));

  MC_CHECK(run_checked(
      Op::AttachToBridge,
      {"ip", "link", "set", alloc.veth_host, "master", alloc.bridge}));
  // Enslaving does not bring the link up, and a down member is a bridge that
  // silently forwards nothing - the classic "bridge link show says it is there
  // but no packets move" trap in docs/networking.md.
  MC_CHECK(run_checked(Op::AttachToBridge,
                       {"ip", "link", "set", alloc.veth_host, "up"}));
  return Ok();
}

// ---------------------------------------------------------------------------
// ip_forwarding_enabled
//
// Not an Expected: a caller wants a yes/no to warn on, and "we could not read
// the sysctl" is indistinguishable from "forwarding is off" for that purpose.
// ---------------------------------------------------------------------------
bool ip_forwarding_enabled() noexcept {
  Expected<std::string> value =
      read_file("/proc/sys/net/ipv4/ip_forward", Op::ReadFile);
  if (!value)
    return false;
  // The file holds a single digit followed by a newline. Scanning for the
  // first digit avoids needing a trim helper and tolerates the missing
  // trailing newline some kernels produce.
  for (char c : *value) {
    if (c == '0')
      return false;
    if (c == '1')
      return true;
  }
  return false;
}

}  // namespace mc
