// SPDX-License-Identifier: MIT
//
// MiniContainer - configuring the container's interfaces from inside the netns.
//
// CHILD-SIDE, so no allocation: this runs between clone() and execve(). That
// rules out shelling out to `ip` (a fork/exec in that window is exactly what
// can deadlock on an inherited malloc lock) and rules out libnetlink. What is
// left is the old SIOC* ioctl interface, which is unglamorous but needs only
// stack structs and a socket fd.
//
// WHY lo IS BROUGHT UP EVEN WITH NO NETWORK
// -----------------------------------------
// A fresh network namespace has a loopback interface, but it is DOWN. Until it
// is up 127.0.0.1 does not work, so a container running a program that talks
// to itself over localhost fails in a way that looks nothing like a networking
// configuration problem. That is why this step runs for NetworkMode::None too,
// and only the veth half is conditional.
//
// THE ioctl INTERFACE IS IPv4-ONLY
// --------------------------------
// SIOCSIFADDR and friends cannot express IPv6. That is a real limitation, and
// the reason this runtime is IPv4-only: doing IPv6 properly needs netlink,
// which needs a buffer strategy compatible with the no-allocation rule.
#include <arpa/inet.h>
#include <net/if.h>
#include <net/route.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#include <errno.h>
#include <unistd.h>

#include <cstring>

#include "minicontainer/container.h"
#include "minicontainer/errors.h"
#include "minicontainer/network.h"

#include <netinet/in.h>

namespace mc {

namespace {

// Parses "10.88.0.2/16" in one pass. inet_pton would handle the address but
// not the suffix, and splitting the string first would need a buffer copy - so
// both halves are parsed together. Returns false on anything malformed rather
// than guessing at a partial parse.
bool parse_cidr(const char* text, ::in_addr_t& addr_out,
                int& prefix_out) noexcept {
  unsigned octets[4] = {0, 0, 0, 0};
  int oi = 0;
  int digits = 0;
  unsigned value = 0;
  const char* p = text;

  for (;; ++p) {
    if (*p >= '0' && *p <= '9') {
      value = value * 10 + static_cast<unsigned>(*p - '0');
      if (value > 255) {
        return false;
      }
      ++digits;
      continue;
    }
    if (*p == '.' || *p == '/' || *p == '\0') {
      if (digits == 0 || oi > 3) {
        return false;
      }
      octets[oi++] = value;
      value = 0;
      digits = 0;
      if (*p == '.') {
        continue;
      }
      break;  // '/' or end of string
    }
    return false;
  }
  if (oi != 4) {
    return false;
  }

  int prefix = 32;
  if (*p == '/') {
    ++p;
    if (*p < '0' || *p > '9') {
      return false;
    }
    prefix = 0;
    for (; *p >= '0' && *p <= '9'; ++p) {
      prefix = prefix * 10 + (*p - '0');
      if (prefix > 32) {
        return false;
      }
    }
    if (*p != '\0') {
      return false;
    }
  }

  // Network byte order, which is what struct sockaddr_in wants.
  addr_out = ::htonl((octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) |
                     octets[3]);
  prefix_out = prefix;
  return true;
}

void set_sockaddr(struct ::ifreq& req, ::in_addr_t addr) noexcept {
  auto* sin = reinterpret_cast<struct ::sockaddr_in*>(&req.ifr_addr);
  std::memset(sin, 0, sizeof(*sin));
  sin->sin_family = AF_INET;
  sin->sin_addr.s_addr = addr;
}

// Sets IFF_UP, preserving the interface's other flags. Reading first matters:
// writing a bare IFF_UP would clear IFF_BROADCAST and IFF_MULTICAST and
// quietly break the interface in ways that surface much later.
bool bring_up(int sock, const char* ifname) noexcept {
  struct ::ifreq req {};
  std::strncpy(req.ifr_name, ifname, IFNAMSIZ - 1);
  if (::ioctl(sock, SIOCGIFFLAGS, &req) != 0) {
    return false;
  }
  req.ifr_flags |= IFF_UP | IFF_RUNNING;
  return ::ioctl(sock, SIOCSIFFLAGS, &req) == 0;
}

}  // namespace

ChildStatus step_configure_address(const ChildContext& ctx) noexcept {
  // AF_INET rather than AF_NETLINK: the SIOC* ioctls can be issued on any
  // socket, and a datagram socket needs no connection or buffer management.
  const int sock = ::socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
  if (sock < 0) {
    return ChildStatus::fail(Op::ConfigureAddress, errno);
  }

  // Loopback first, and unconditionally - see the header comment.
  if (ctx.configure_loopback && !bring_up(sock, "lo")) {
    const int err = errno;
    ::close(sock);
    return ChildStatus::fail(Op::ConfigureAddress, err);
  }

  // NetworkMode::None stops here: loopback works, nothing else exists.
  if (ctx.container_ip_cidr == nullptr || ctx.veth_name == nullptr) {
    ::close(sock);
    return ChildStatus::success();
  }

  ::in_addr_t addr = 0;
  int prefix = 0;
  if (!parse_cidr(ctx.container_ip_cidr, addr, prefix)) {
    ::close(sock);
    return ChildStatus::fail(Op::ConfigureAddress, EINVAL);
  }

  struct ::ifreq req {};
  std::strncpy(req.ifr_name, ctx.veth_name, IFNAMSIZ - 1);

  set_sockaddr(req, addr);
  if (::ioctl(sock, SIOCSIFADDR, &req) != 0) {
    const int err = errno;
    ::close(sock);
    return ChildStatus::fail(Op::ConfigureAddress, err);
  }

  // The netmask is a separate call, and must precede bringing the link up: the
  // kernel derives the on-link route from it, and a wrong mask produces an
  // interface that cannot reach anything on its own subnet.
  const ::in_addr_t mask =
      prefix == 0 ? 0 : ::htonl(0xFFFFFFFFu << (32 - prefix));
  set_sockaddr(req, mask);
  if (::ioctl(sock, SIOCSIFNETMASK, &req) != 0) {
    const int err = errno;
    ::close(sock);
    return ChildStatus::fail(Op::ConfigureAddress, err);
  }

  if (!bring_up(sock, ctx.veth_name)) {
    const int err = errno;
    ::close(sock);
    return ChildStatus::fail(Op::ConfigureAddress, err);
  }

  // The default route last: the gateway must be on-link, which it only becomes
  // once the address and mask above are in place.
  if (ctx.gateway_ip != nullptr && ctx.gateway_ip[0] != '\0') {
    ::in_addr_t gw = 0;
    int gw_prefix = 0;
    if (!parse_cidr(ctx.gateway_ip, gw, gw_prefix)) {
      ::close(sock);
      return ChildStatus::fail(Op::ConfigureAddress, EINVAL);
    }

    struct ::rtentry route {};
    auto* dst = reinterpret_cast<struct ::sockaddr_in*>(&route.rt_dst);
    auto* gwa = reinterpret_cast<struct ::sockaddr_in*>(&route.rt_gateway);
    auto* msk = reinterpret_cast<struct ::sockaddr_in*>(&route.rt_genmask);
    dst->sin_family = AF_INET;
    dst->sin_addr.s_addr = 0;  // 0.0.0.0/0 - the default route
    msk->sin_family = AF_INET;
    msk->sin_addr.s_addr = 0;
    gwa->sin_family = AF_INET;
    gwa->sin_addr.s_addr = gw;
    route.rt_flags = RTF_UP | RTF_GATEWAY;

    if (::ioctl(sock, SIOCADDRT, &route) != 0) {
      const int err = errno;
      ::close(sock);
      return ChildStatus::fail(Op::ConfigureAddress, err);
    }
  }

  ::close(sock);
  return ChildStatus::success();
}

}  // namespace mc
