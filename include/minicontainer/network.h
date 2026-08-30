// SPDX-License-Identifier: MIT
//
// MiniContainer - Tier 2: container networking.
//
// TWO SIDES, TWO NAMESPACES
// -------------------------
// Host side (parent, host netns): create the bridge, create a veth pair, move
// one end into the container's netns, attach the other to the bridge, add NAT
// and port-forward rules. Ordinary allocating code.
//
// Container side (child, new netns): bring up lo, give the veth an address,
// add the default route. That runs post-clone under container.h's
// no-allocation rule, so it is a single ChildStatus step.
//
// THE ORDERING TRAP
// -----------------
// The veth peer must be moved into the container's netns while the child is
// still blocked on the sync pipe. Move it too late and the child has already
// tried to configure an interface that does not exist yet; earlier is
// impossible, since the netns does not exist until clone() returns. That is
// why network setup sits between clone() and the 'G' byte in the handshake.
//
// WSL2 IS DOUBLE-NATTED
// ---------------------
// A bridge and NAT inside WSL2 give containers outbound connectivity, but
// inbound from Windows needs `netsh interface portproxy` on the Windows side
// as well - the WSL VM is itself behind a NAT. -p therefore configures the
// Linux half and reports the netsh command the user must run. See
// docs/networking.md.
#pragma once

#include <sys/types.h>

#include <string>
#include <vector>

#include "minicontainer/config.h"
#include "minicontainer/container.h"
#include "minicontainer/errors.h"

namespace mc {

// Everything created on the host for one container, so teardown is exact: we
// only ever remove interfaces and rules we made ourselves.
struct NetworkAllocation {
  std::string veth_host;       // "mc-a1b2c3d4" on the host side
  std::string veth_container;  // "eth0" inside the container
  std::string ip_cidr;         // "10.88.0.2/16"
  std::string gateway;         // "10.88.0.1"
  std::string bridge;          // "mc-br0"
  bool nat_configured = false;
  std::vector<PortMapping> published;
};

// Creates the bridge if absent, assigns it the gateway address, and brings it
// up. Idempotent: an existing bridge with the right address is left alone.
Expected<void> ensure_bridge(const NetworkConfig& net);

// Picks a free address in the configured subnet. The addresses already in use
// are passed in rather than read from the state store here, so this stays
// testable without a live state directory.
Expected<std::string> allocate_ip(const NetworkConfig& net,
                                  const std::vector<std::string>& taken);

// Creates the veth pair and moves the container end into `pid`'s netns. Must
// be called after clone() and before releasing the child.
Expected<void> create_veth_pair(const NetworkAllocation& alloc, ::pid_t pid);

// Attaches the host end to the bridge and brings it up.
Expected<void> attach_to_bridge(const NetworkAllocation& alloc);

// MASQUERADE for traffic leaving the subnet, plus the forward rules that let
// the bridge route at all. Idempotent - checks before inserting, so repeated
// container starts do not stack duplicate rules.
Expected<void> configure_nat(const NetworkConfig& net);

// DNAT rules for -p. Returns the `netsh` commands a Windows user additionally
// needs; empty on native Linux.
Expected<std::vector<std::string>> configure_port_mappings(
    const NetworkAllocation& alloc);

// Removes every interface and rule the allocation records. Best-effort by
// design: teardown must not abort partway and strand the rest, so it collects
// failures and reports them together rather than returning on the first.
Expected<void> teardown_network(const NetworkAllocation& alloc);

// True when net.ipv4.ip_forward is 1. Bridge mode without it silently gives
// containers a network they cannot route out of - a confusing failure worth
// catching up front.
bool ip_forwarding_enabled() noexcept;

// ---------------------------------------------------------------------------
// Child side. No allocation.
// ---------------------------------------------------------------------------

// Brings up lo, assigns ctx.container_ip_cidr to ctx.veth_name, and adds the
// default route via ctx.gateway_ip. When container_ip_cidr is null it still
// brings up lo, which is what makes 127.0.0.1 work under NetworkMode::None.
ChildStatus step_configure_address(const ChildContext& ctx) noexcept;

}  // namespace mc
