// SPDX-License-Identifier: MIT
//
// MiniContainer - veth pair creation and address allocation.
//
// A veth pair is the only way to give a network namespace a link to anywhere
// else: it is a virtual cable with an interface at each end, and moving one
// end into a namespace is what connects that namespace to the host. There is
// no "just attach the netns to the bridge" operation - the pair is the
// mechanism.
//
// THE ORDERING CONSTRAINT
// -----------------------
// create_veth_pair() must run AFTER clone() (the target netns does not exist
// before that) and BEFORE the child is released from the sync pipe (the child
// configures an interface that must already be there). That window is exactly
// what the three-pipe handshake in process.h exists to create, and it is why
// this function takes a pid rather than doing the clone itself.
#include <sys/types.h>

#include <cstdint>
#include <string>
#include <vector>

#include "minicontainer/errors.h"
#include "minicontainer/network.h"

#include "internal.h"

namespace mc {

using net_detail::format_ipv4;
using net_detail::Ipv4Cidr;
using net_detail::parse_ipv4;
using net_detail::parse_ipv4_cidr;
using net_detail::run_checked;
using net_detail::validate_ifname;

Expected<std::string> allocate_ip(const NetworkConfig& net,
                                  const std::vector<std::string>& taken) {
  const Ipv4Cidr subnet =
      MC_TRY(parse_ipv4_cidr(net.subnet_cidr, Op::ConfigureAddress));

  // /31 and /32 leave no room for a gateway plus a host; rejecting them here
  // is clearer than allocating an address and then failing to route from it.
  if (subnet.prefix > 30) {
    return Err(Error::invalid(
        Op::ConfigureAddress,
        "subnet " + net.subnet_cidr +
            " is too small to host containers; use /30 or larger"));
  }

  const std::uint32_t gateway =
      MC_TRY(parse_ipv4(net.gateway_ip, Op::ConfigureAddress));

  // Host bits, e.g. 16 for a /16. Computed in 64 bits because a /0 would
  // overflow a 32-bit shift and make the expression undefined.
  const int host_bits = 32 - subnet.prefix;
  const std::uint64_t span = 1ULL << host_bits;

  // Normalise the taken list to integers once rather than re-parsing per
  // candidate. An entry that will not parse is skipped rather than fatal: a
  // corrupt record for one container must not block starting another.
  std::vector<std::uint32_t> used;
  used.reserve(taken.size());
  for (const std::string& t : taken) {
    const std::string addr = t.substr(0, t.find('/'));
    Expected<std::uint32_t> parsed = parse_ipv4(addr, Op::ConfigureAddress);
    if (parsed) {
      used.push_back(*parsed);
    }
  }

  // Skip offset 0 (the network address) and stop before the last (broadcast).
  for (std::uint64_t offset = 1; offset + 1 < span; ++offset) {
    const std::uint32_t candidate =
        subnet.network + static_cast<std::uint32_t>(offset);
    if (candidate == gateway) {
      continue;
    }
    bool is_used = false;
    for (std::uint32_t u : used) {
      if (u == candidate) {
        is_used = true;
        break;
      }
    }
    if (!is_used) {
      return format_ipv4(candidate) + "/" + std::to_string(subnet.prefix);
    }
  }

  return Err(Error::invalid(
      Op::ConfigureAddress,
      "no free address left in " + net.subnet_cidr + " (" +
          std::to_string(taken.size()) +
          " already allocated); remove some containers or widen the subnet"));
}

std::string veth_peer_temp_name(const std::string& veth_host) {
  // veth_host is always "mc-" + 12 hex chars (launch.cpp's convention), so
  // swapping the second letter yields "mp-" + the same 12 hex chars: the
  // same length (already within IFNAMSIZ), guaranteed different from
  // veth_host, and virtually certain not to collide with a real interface on
  // any host, unlike the literal "eth0" this replaces.
  std::string temp = veth_host;
  if (temp.size() >= 2) {
    temp[1] = 'p';
  }
  return temp;
}

Expected<void> create_veth_pair(const NetworkAllocation& alloc, ::pid_t pid) {
  const std::string peer = veth_peer_temp_name(alloc.veth_host);

  MC_CHECK(validate_ifname(alloc.veth_host, Op::CreateVeth));
  MC_CHECK(validate_ifname(peer, Op::CreateVeth));

  // Creating the pair names both ends at once; there is no way to create one
  // half. Both names must therefore be free, and a leftover interface from a
  // crashed run is the usual reason this fails with EEXIST. The peer is
  // deliberately NOT alloc.veth_container ("eth0") - see veth_peer_temp_name.
  MC_CHECK(run_checked(Op::CreateVeth, {"ip", "link", "add", alloc.veth_host,
                                        "type", "veth", "peer", "name", peer}));

  // Move the peer into the target namespace. After this the container end is
  // invisible to the host, which is why teardown cannot address it by name -
  // it deletes the HOST end, and the kernel removes the peer along with it.
  Expected<void> moved =
      run_checked(Op::MoveVethToNetns,
                  {"ip", "link", "set", peer, "netns", std::to_string(pid)});
  if (!moved) {
    // The pair exists but is stranded in the host namespace. Remove it before
    // returning, or the next attempt fails with EEXIST on a name that looks
    // like it should be free.
    (void)run_checked(Op::TeardownNetwork,
                      {"ip", "link", "del", alloc.veth_host});
    return moved;
  }

  return Ok();
}

}  // namespace mc
