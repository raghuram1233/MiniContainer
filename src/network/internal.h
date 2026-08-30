// SPDX-License-Identifier: MIT
//
// MiniContainer - the network module's internal shared surface.
//
// These helpers are used by every translation unit in src/network/ but are
// deliberately NOT in include/minicontainer/network.h: nothing outside this
// module should be running `ip` commands or parsing CIDRs, and putting them in
// the public header would invite exactly that.
//
// The alternative - repeating the declarations verbatim in each .cpp - was the
// original shape, and it is the sort of duplication that silently rots the
// moment one copy's signature changes. One header is cheaper.
#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "minicontainer/errors.h"

namespace mc {
namespace net_detail {

struct CommandResult {
  int exit_code = -1;  // -1 when the process died on a signal
  std::string out;
  std::string err;
};

// Runs argv via fork/execvp - never system(), and never a composed shell
// string. A container name reaching a shell would be a command injection, and
// the argv form makes that structurally impossible rather than merely
// unlikely.
Expected<CommandResult> run_command(const std::vector<std::string>& argv);

// Runs argv and turns a non-zero exit into an Error carrying the command and
// its stderr. A bare "iptables failed" is useless to debug.
Expected<void> run_checked(Op op, const std::vector<std::string>& argv);

// For probes where a non-zero exit is an expected answer ("does this link
// exist?") rather than a failure.
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

// Interface names are bounded by IFNAMSIZ and must not contain '/' or
// whitespace. Checked before every `ip` invocation so a malformed name fails
// here with a clear message rather than as an opaque iproute2 usage error.
Expected<void> validate_ifname(std::string_view name, Op op);

// Split out from running_under_wsl() so it can be unit-tested with a supplied
// string instead of whatever the test host happens to be.
bool osrelease_indicates_wsl(std::string_view osrelease) noexcept;
bool running_under_wsl() noexcept;

}  // namespace net_detail
}  // namespace mc
