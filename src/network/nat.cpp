// SPDX-License-Identifier: MIT
//
// MiniContainer - NAT, port publishing, and teardown.
//
// WHY NAT AT ALL
// --------------
// The container's address lives in a private subnet (10.88.0.0/16 by default)
// that nothing outside this host routes to. Masquerading rewrites the source
// address of packets leaving that subnet to the host's own, so replies come
// back to the host, which un-rewrites them. Without it a container has an
// address, a route, and no connectivity - which looks like a DNS problem and
// is not.
//
// EVERY RULE IS CHECKED BEFORE IT IS ADDED
// ----------------------------------------
// iptables has no "add if absent". Running `iptables -A` twice inserts the
// rule twice, and a rule added on every container start accumulates until the
// chain has thousands of entries and packets visibly slow down. `-C` tests for
// a rule without adding it, so every add here is guarded by one.
//
// TEARDOWN COLLECTS FAILURES INSTEAD OF STOPPING
// ----------------------------------------------
// Returning on the first teardown failure would strand every resource after
// it - and teardown is exactly the path that runs when something has already
// gone wrong. So each step runs regardless, and failures are reported together
// at the end.
#include <cstddef>
#include <string>
#include <vector>

#include "minicontainer/errors.h"
#include "minicontainer/network.h"

#include "internal.h"

namespace mc {

using net_detail::CommandResult;
using net_detail::join_command;
using net_detail::run_checked;
using net_detail::run_command;
using net_detail::run_succeeds;
using net_detail::running_under_wsl;

namespace {

// Builds an iptables argv: ["iptables", <table...>, <verb>, <rule...>].
// The check and add forms differ only in the verb, which is what makes the
// idempotence below a two-line affair rather than string surgery.
std::vector<std::string> iptables_argv(const std::vector<std::string>& table,
                                       const char* verb,
                                       const std::vector<std::string>& rule) {
  std::vector<std::string> argv{"iptables"};
  argv.insert(argv.end(), table.begin(), table.end());
  argv.push_back(verb);
  argv.insert(argv.end(), rule.begin(), rule.end());
  return argv;
}

// -C tests whether the rule is present; -A appends it. Doing both is what
// keeps repeated container starts from stacking duplicates.
Expected<void> ensure_rule(Op op, const std::vector<std::string>& table,
                           const std::vector<std::string>& rule) {
  const bool present = MC_TRY(run_succeeds(iptables_argv(table, "-C", rule)));
  if (present) {
    return Ok();
  }
  return run_checked(op, iptables_argv(table, "-A", rule));
}

// The DNAT rule pair for one published port, in the order teardown removes
// them. Kept in one place so add and delete cannot drift apart - a delete that
// does not exactly match its add silently leaves the rule behind.
std::vector<std::vector<std::string>> port_rules(const PortMapping& p,
                                                 const std::string& ip) {
  const std::string dest = ip + ":" + std::to_string(p.container_port);
  const std::string dport = std::to_string(p.host_port);
  return {
      {"PREROUTING", "-p", p.protocol, "--dport", dport, "-j", "DNAT",
       "--to-destination", dest},
      // Traffic originating on the host itself takes OUTPUT, not PREROUTING.
      // Without this, `curl localhost:8080` on the host misses the mapping
      // while an external client hits it - a genuinely confusing asymmetry.
      {"OUTPUT", "-p", p.protocol, "-d", "127.0.0.1", "--dport", dport, "-j",
       "DNAT", "--to-destination", dest},
  };
}

}  // namespace

Expected<void> configure_nat(const NetworkConfig& net) {
  // Masquerade anything leaving the container subnet by a route other than the
  // bridge itself. The "! -o bridge" is what stops container-to-container
  // traffic on the same bridge from being pointlessly rewritten.
  MC_CHECK(ensure_rule(Op::ConfigureNat, {"-t", "nat"},
                       {"POSTROUTING", "-s", net.subnet_cidr, "!", "-o",
                        net.bridge_name, "-j", "MASQUERADE"}));

  // Even with masquerading, FORWARD must permit the traffic. Many hosts
  // default FORWARD to DROP, which is the other half of the "container has an
  // address but no connectivity" symptom.
  MC_CHECK(ensure_rule(Op::ConfigureNat, {},
                       {"FORWARD", "-i", net.bridge_name, "!", "-o",
                        net.bridge_name, "-j", "ACCEPT"}));
  MC_CHECK(ensure_rule(Op::ConfigureNat, {},
                       {"FORWARD", "-o", net.bridge_name, "-m", "conntrack",
                        "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"}));
  return Ok();
}

Expected<std::vector<std::string>> configure_port_mappings(
    const NetworkAllocation& alloc) {
  // DNAT wants a bare address, without the prefix.
  const std::string ip = alloc.ip_cidr.substr(0, alloc.ip_cidr.find('/'));

  for (const PortMapping& p : alloc.published) {
    for (const std::vector<std::string>& rule : port_rules(p, ip)) {
      MC_CHECK(ensure_rule(Op::ConfigurePortMap, {"-t", "nat"}, rule));
    }
  }

  // On WSL2 the Linux side is only half the path: the WSL VM sits behind its
  // own NAT, so a port published here stays unreachable from Windows until a
  // portproxy forwards it. netsh cannot be run from inside WSL, so hand the
  // user the exact command rather than leaving them to discover the gap.
  std::vector<std::string> netsh;
  if (running_under_wsl()) {
    for (const PortMapping& p : alloc.published) {
      const std::string port = std::to_string(p.host_port);
      netsh.push_back("netsh interface portproxy add v4tov4 listenport=" +
                      port + " listenaddress=0.0.0.0 connectport=" + port +
                      " connectaddress=$(wsl hostname -I)");
    }
  }
  return netsh;
}

Expected<void> teardown_network(const NetworkAllocation& alloc) {
  std::vector<std::string> failures;

  // Port rules first: they name the container address, which stops meaning
  // anything the moment the veth goes.
  if (!alloc.ip_cidr.empty()) {
    const std::string ip = alloc.ip_cidr.substr(0, alloc.ip_cidr.find('/'));
    for (const PortMapping& p : alloc.published) {
      for (const std::vector<std::string>& rule : port_rules(p, ip)) {
        const std::vector<std::string> del =
            iptables_argv({"-t", "nat"}, "-D", rule);
        Expected<CommandResult> r = run_command(del);
        // A rule that is already gone is the expected case on a repeat
        // teardown, so only a failure to run iptables at all is reportable.
        if (!r) {
          failures.push_back(join_command(del) + ": " + r.error().message());
        }
      }
    }
  }

  // Deleting the host end removes the pair; the container end goes with it,
  // and is unreachable by name from here anyway.
  if (!alloc.veth_host.empty()) {
    const std::vector<std::string> del{"ip", "link", "del", alloc.veth_host};
    Expected<CommandResult> r = run_command(del);
    if (!r) {
      failures.push_back(join_command(del) + ": " + r.error().message());
    }
  }

  // The bridge is deliberately NOT removed: it is shared by every container,
  // and tearing it down here would disconnect the others.

  if (!failures.empty()) {
    std::string all;
    for (const std::string& f : failures) {
      if (!all.empty()) {
        all += "; ";
      }
      all += f;
    }
    return Err(Error::invalid(Op::TeardownNetwork,
                              "network teardown was incomplete: " + all));
  }
  return Ok();
}

}  // namespace mc
