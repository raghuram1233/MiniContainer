# Networking

Status: **Planned.** No network module exists yet in `src/network/`. The
`NetworkMode`, `NetworkConfig`, and `PortMapping` types in
`include/minicontainer/config.h`, and the networking `Op` enumerators in
`errors.h` (`CreateBridge`, `CreateVeth`, `MoveVethToNetns`, `AttachToBridge`,
`ConfigureNat`, `ConfigurePortMap`, `TeardownNetwork`, `ConfigureAddress`)
define the intended design. This document also covers a WSL2-specific
limitation that is real and worth understanding rather than glossing over.

## The problem it solves

A network namespace (`CLONE_NEWNET`, see `docs/namespaces.md`) gives a
process its own network stack — but by itself, a fresh network namespace has
*only loopback*, and even that starts down. A container needs a way to talk
to the outside world (and, for published ports, a way for the outside world
to reach back in) without simply sharing the host's network stack, which
would mean two containers can't both bind port 80.

## `NetworkMode`

MiniContainer's `NetworkConfig::mode` (`config.h`) has three settings:

- **`None`**: `CLONE_NEWNET` is created, only loopback is brought up. No
  external connectivity at all — appropriate for CPU-bound batch work that
  needs isolation but never talks to a network.
- **`Bridge`**: a veth pair connects the container's netns to a
  MiniContainer-managed Linux bridge on the host, with NAT for outbound
  traffic. This is the mode that needs everything below.
- **`Host`**: no `CLONE_NEWNET` at all — the container shares the host's
  network namespace outright. Fast and simple, but means the container can
  bind any port the host can and can see every host network interface;
  effectively no network isolation.

## veth pairs

A **veth pair** is two virtual Ethernet interfaces that are always created
together and always connected to each other — anything sent in one end
comes out the other, like a virtual patch cable. `CreateVeth` creates the
pair on the host; `MoveVethToNetns` moves *one end* of it into the
container's network namespace (`ip link set <veth-peer> netns <pid>`),
leaving the other end on the host side. This is what actually crosses the
namespace boundary — the network namespace itself has no innate connection
to anything until a veth (or similar) end is placed inside it.

## The Linux bridge

A **bridge** (`brctl`/`ip link add type bridge`, MiniContainer's default
`mc-br0`) is a kernel-level software Ethernet switch. The host end of every
container's veth pair attaches to the same bridge (`AttachToBridge`), which
is what lets multiple containers on the same bridge reach each other
directly, the way multiple machines on a physical switch would, all sharing
one `subnet_cidr` (default `10.88.0.0/16`, with `gateway_ip` `10.88.0.1`,
usually an address on the bridge itself).

## NAT (masquerading)

For a container to reach the *outside* internet (not just other
containers on the same bridge), its private `10.88.0.0/16` traffic needs
to be source-NAT'd to the host's real outbound address before it leaves the
host — otherwise return traffic has nowhere valid to route back to.
`ConfigureNat` sets this up with an iptables (nf_tables backend, per this
project's toolchain) MASQUERADE rule on the host's outbound interface:

```bash
iptables -t nat -A POSTROUTING -s 10.88.0.0/16 ! -o mc-br0 -j MASQUERADE
```

`enable_nat` in `NetworkConfig` gates whether this rule is installed at
all; `PortMapping`/`ConfigurePortMap` is the inbound counterpart — a
DNAT rule that redirects a host port to a container's private IP:port so
external traffic can reach an internal service (`iptables -t nat -A
PREROUTING -p tcp --dport 8080 -j DNAT --to-destination
10.88.0.5:80`, roughly).

## The WSL2-specific reality: double NAT

This is the part of container networking that a Linux-native tutorial
won't mention, and it is a real, documented limitation of running this
project's target environment on Windows via WSL2, not a MiniContainer bug.

WSL2 itself runs inside a lightweight Hyper-V VM. **The WSL2 VM's network
is itself behind NAT from the Windows host's perspective** — Windows
assigns the WSL2 VM an address on an internal virtual switch and NATs
traffic between it and the outside world. So a container's published port
inside WSL2 sits behind **two layers of NAT**: container -> WSL2 VM (the
layer MiniContainer's own bridge/NAT sets up) -> Windows host (the layer
WSL2 itself sets up, outside MiniContainer's control). A port published by
`docker run -p 8080:80` (or the MiniContainer equivalent) is reachable from
*inside* the WSL2 VM immediately, but **not automatically reachable from
Windows** (e.g. from a browser on the Windows desktop, or from another
machine on the LAN) without an extra step, because Windows doesn't
automatically know to forward that port through into the WSL2 VM.

Two ways to close that last hop, neither of which MiniContainer controls or
automates:

1. **Mirrored networking** (`.wslconfig`: `[wsl2] networkingMode=mirrored`,
   available on recent Windows 11 builds) — the WSL2 VM shares the Windows
   host's network interface directly rather than being NAT'd behind it,
   which removes the outer NAT layer entirely.
2. **`netsh interface portproxy`** — a manual Windows-side port forward
   from a Windows-visible address into the WSL2 VM's address:
   ```powershell
   netsh interface portproxy add v4tov4 `
     listenaddress=0.0.0.0 listenport=8080 `
     connectaddress=<wsl2-vm-ip> connectport=8080
   ```
   The WSL2 VM's IP changes on every restart unless pinned, so this needs
   to be re-run (or scripted) after a WSL restart.

**This is a documented limitation, not a hidden one**: publishing a
container port to be reachable from the Windows side of a WSL2 development
box requires one of the two steps above, on top of whatever MiniContainer
itself does inside the WSL2 VM. It is exactly the kind of gap a production
runtime would abstract away with a portproxy sync daemon; MiniContainer
does not attempt to, because that daemon is Windows integration plumbing,
not a Linux systems-programming lesson.

## Failure modes and common mistakes

- **Forgetting the network namespace starts with loopback down** —
  `ConfigureAddress` must bring up `lo` (`ip link set lo up`) even in
  `NetworkMode::None`, or even fully-local traffic (a process connecting to
  `127.0.0.1` inside the container) fails.
- **Attaching the veth's host end to the bridge before the container end
  has an address** — order matters less here than in the namespace
  handshake, but a bridge with no members forwarding correctly is a common
  early debugging trap; verify with `bridge link show`.
- **Expecting a published port to be reachable from Windows without
  mirrored networking or a portproxy rule** — see above; this is the WSL2
  double-NAT gap, not a MiniContainer bug.
- **iptables rules not surviving a WSL2 restart** — the WSL2 VM is
  ephemeral across full shutdowns; any NAT/portproxy setup done by hand
  needs to be reapplied, which is why `ConfigureNat`/`ConfigurePortMap`
  need to run as part of container startup every time, not be treated as a
  one-time host setup step.

## How to debug it

```bash
ip netns list                              # (if using named netns) list network namespaces
nsenter -t <pid> -n ip addr                # interfaces inside a container's netns
nsenter -t <pid> -n ip route                # routing table inside the container
bridge link show                            # what's attached to mc-br0
iptables -t nat -L -n -v                    # NAT/masquerade/DNAT rules currently active
ss -tlnp                                    # what's actually listening, and where
tcpdump -i mc-br0                           # observe traffic crossing the bridge
```

From the Windows side, checking the WSL2 VM's current address (needed for
`netsh portproxy`):

```powershell
wsl -d Ubuntu-24.04 -- ip -4 addr show eth0
```

## Security implications

`NetworkMode::Host` gives up all network isolation — a container in this
mode can bind any host port and observe/interact with every host network
interface, so it should be an explicit, rare opt-in, never a default.
Bridge mode's NAT/DNAT rules are host-wide iptables state — a bug that
installs an overly broad DNAT rule (e.g. matching more source traffic than
intended) affects the whole host's routing, not just one container, which
is why `TeardownNetwork` removing exactly the rules a specific container's
setup added (and no more) matters for correctness as well as hygiene.

## Likely interview questions

- *"How does a container reach the internet through a bridge network?"* —
  Its veth peer sends packets to the bridge, which forwards them to the
  host's real interface; a NAT/MASQUERADE rule rewrites the source address
  from the container's private IP to the host's routable one so return
  traffic can find its way back.
- *"Why can't two containers on host networking both bind port 80?"* —
  They share one network namespace with the host, hence one socket
  namespace for that stack — port binding is a stack-wide resource, exactly
  what `CLONE_NEWNET` exists to privatize per container.
- *"You published a port with `-p 8080:80` inside WSL2 but can't reach it
  from your Windows browser — why?"* — WSL2's own VM networking NATs
  between the VM and Windows; the container-to-host-VM NAT layer worked
  correctly, but there's a second NAT hop (VM-to-Windows) that needs
  mirrored networking or a `netsh portproxy` rule to cross — this is a WSL2
  platform limitation, not a container networking bug.
- *"What's the difference between a veth pair and a bridge?"* — A veth pair
  is a point-to-point virtual cable between exactly two endpoints; a bridge
  is a virtual switch that many veth pairs (and other interfaces) can
  attach to, enabling any-to-any forwarding among its members.
