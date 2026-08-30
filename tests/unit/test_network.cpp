// SPDX-License-Identifier: MIT
//
// Unit tests for the pure logic of src/network/: address allocation
// (allocate_ip), the hand-rolled IPv4/CIDR parsers and formatters, the
// interface-name validator, and the WSL osrelease predicate.
//
// Nothing here creates an interface, runs `ip` or `iptables`, or touches the
// host in any way. Every function under test is a pure function of its
// arguments - that is precisely why they were factored out: allocate_ip()
// takes the in-use address list as a parameter instead of reading the state
// store, and osrelease_indicates_wsl() takes the release string instead of
// reading /proc/sys/kernel/osrelease. The parts that do run commands
// (ensure_bridge, create_veth_pair, configure_nat) need root and a real
// kernel, and live in the integration suite.
//
// internal.h is the network module's private header, so it is included by
// relative path: src/ is deliberately not on the test target's include path.

#include <cstdint>
#include <string>
#include <vector>

#include "minicontainer/config.h"
#include "minicontainer/errors.h"
#include "minicontainer/network.h"

#include "../../src/network/internal.h"

#include <gtest/gtest.h>

using mc::net_detail::format_cidr;
using mc::net_detail::format_ipv4;
using mc::net_detail::Ipv4Cidr;
using mc::net_detail::osrelease_indicates_wsl;
using mc::net_detail::parse_ipv4;
using mc::net_detail::parse_ipv4_cidr;
using mc::net_detail::validate_ifname;

namespace {

constexpr mc::Op kOp = mc::Op::ConfigureAddress;

mc::NetworkConfig net_with(std::string subnet, std::string gateway) {
  mc::NetworkConfig net;
  net.mode = mc::NetworkMode::Bridge;
  net.subnet_cidr = std::move(subnet);
  net.gateway_ip = std::move(gateway);
  return net;
}

std::uint32_t addr(const char* text) {
  const mc::Expected<std::uint32_t> a = parse_ipv4(text, kOp);
  EXPECT_TRUE(a.has_value()) << "test fixture address did not parse: " << text;
  return a.value_or(0);
}

}  // namespace

// ---------------------------------------------------------------------------
// allocate_ip - the centrepiece. Handing out a duplicate, or the gateway's own
// address, breaks the container silently and at runtime rather than here.
// ---------------------------------------------------------------------------
TEST(IpAllocationTest, FirstFreeAddressInASlash16) {
  const mc::NetworkConfig net = net_with("10.88.0.0/16", "10.88.0.1");
  const mc::Expected<std::string> ip = mc::allocate_ip(net, {});
  ASSERT_TRUE(ip.has_value()) << ip.error().message();
  // .0 is the network address and .1 is the gateway, so the first container
  // gets .2. The returned string carries the subnet's prefix, not /32: the
  // container needs an on-link route to the rest of the bridge.
  EXPECT_EQ(*ip, "10.88.0.2/16");
}

TEST(IpAllocationTest, FirstFreeAddressInASlash24) {
  const mc::NetworkConfig net = net_with("192.168.5.0/24", "192.168.5.1");
  const mc::Expected<std::string> ip = mc::allocate_ip(net, {});
  ASSERT_TRUE(ip.has_value()) << ip.error().message();
  EXPECT_EQ(*ip, "192.168.5.2/24");
}

TEST(IpAllocationTest, HostBitsOfTheSubnetAreIgnored) {
  // parse_ipv4_cidr masks the address, so a config written as 10.88.7.9/16
  // still allocates out of 10.88.0.0/16 rather than starting at .7.9.
  const mc::NetworkConfig net = net_with("10.88.7.9/16", "10.88.0.1");
  const mc::Expected<std::string> ip = mc::allocate_ip(net, {});
  ASSERT_TRUE(ip.has_value()) << ip.error().message();
  EXPECT_EQ(*ip, "10.88.0.2/16");
}

TEST(IpAllocationTest, SkipsAddressesAlreadyTaken) {
  const mc::NetworkConfig net = net_with("10.88.0.0/16", "10.88.0.1");
  const std::vector<std::string> taken = {"10.88.0.2/16", "10.88.0.3/16"};
  const mc::Expected<std::string> ip = mc::allocate_ip(net, taken);
  ASSERT_TRUE(ip.has_value()) << ip.error().message();
  EXPECT_EQ(*ip, "10.88.0.4/16");
}

TEST(IpAllocationTest, TakenEntriesMayBeBareAddressesOrCidrs) {
  // The state store records "10.88.0.2/16"; a hand-edited or older record may
  // hold the bare address. Both must be honoured, or the runtime hands the
  // same address to two containers.
  const mc::NetworkConfig net = net_with("10.88.0.0/16", "10.88.0.1");
  const mc::Expected<std::string> ip =
      mc::allocate_ip(net, {"10.88.0.2", "10.88.0.3/16"});
  ASSERT_TRUE(ip.has_value()) << ip.error().message();
  EXPECT_EQ(*ip, "10.88.0.4/16");
}

TEST(IpAllocationTest, SkipsTheGatewayAddress) {
  // Allocating the gateway's own address would break every container on the
  // bridge, not just this one: the bridge would answer for an address a
  // container also claims, and the default route would stop working
  // host-wide. The skip must therefore be by value, not by "offset 1".
  const mc::NetworkConfig net = net_with("10.88.0.0/24", "10.88.0.3");
  const mc::Expected<std::string> ip =
      mc::allocate_ip(net, {"10.88.0.1", "10.88.0.2"});
  ASSERT_TRUE(ip.has_value()) << ip.error().message();
  EXPECT_EQ(*ip, "10.88.0.4/24");
}

TEST(IpAllocationTest, GatewayElsewhereFreesTheFirstHostAddress) {
  // The complement of the test above: with the gateway at .3, .1 is an
  // ordinary host address and must be handed out.
  const mc::NetworkConfig net = net_with("10.88.0.0/24", "10.88.0.3");
  const mc::Expected<std::string> ip = mc::allocate_ip(net, {});
  ASSERT_TRUE(ip.has_value()) << ip.error().message();
  EXPECT_EQ(*ip, "10.88.0.1/24");
}

TEST(IpAllocationTest, RejectsSubnetsTooSmallToHostAnything) {
  // A /31 has two addresses and a /32 one, leaving no room for a gateway plus
  // a container. Refusing here is clearer than allocating an address that
  // cannot route.
  for (const char* cidr : {"10.88.0.0/31", "10.88.0.0/32"}) {
    const mc::NetworkConfig net = net_with(cidr, "10.88.0.1");
    const mc::Expected<std::string> ip = mc::allocate_ip(net, {});
    ASSERT_FALSE(ip.has_value()) << "accepted " << cidr;
    EXPECT_EQ(ip.error().op(), mc::Op::ConfigureAddress);
    EXPECT_NE(ip.error().message().find("too small"), std::string::npos);
  }
}

TEST(IpAllocationTest, AcceptsASlash30AsTheSmallestUsableSubnet) {
  // /30: .0 network, .1 gateway, .2 the single container, .3 broadcast.
  const mc::NetworkConfig net = net_with("10.88.0.0/30", "10.88.0.1");
  const mc::Expected<std::string> ip = mc::allocate_ip(net, {});
  ASSERT_TRUE(ip.has_value()) << ip.error().message();
  EXPECT_EQ(*ip, "10.88.0.2/30");
}

TEST(IpAllocationTest, ExhaustionIsAnErrorNotADuplicate) {
  // The one failure mode that must never be silent: with the /30's only host
  // address taken, returning it a second time would give two containers the
  // same IP and produce an intermittent, near-undebuggable network fault.
  const mc::NetworkConfig net = net_with("10.88.0.0/30", "10.88.0.1");
  const mc::Expected<std::string> ip = mc::allocate_ip(net, {"10.88.0.2/30"});
  ASSERT_FALSE(ip.has_value());
  EXPECT_EQ(ip.error().op(), mc::Op::ConfigureAddress);
  EXPECT_NE(ip.error().message().find("no free address"), std::string::npos);
}

TEST(IpAllocationTest, MalformedSubnetIsAnError) {
  for (const char* cidr : {"10.88.0.0", "10.88.0.0/33", "not-an-ip/16",
                           "10.88.0.256/16", "", "/16"}) {
    const mc::NetworkConfig net = net_with(cidr, "10.88.0.1");
    const mc::Expected<std::string> ip = mc::allocate_ip(net, {});
    EXPECT_FALSE(ip.has_value()) << "accepted subnet '" << cidr << "'";
  }
}

TEST(IpAllocationTest, MalformedGatewayIsAnError) {
  const mc::NetworkConfig net = net_with("10.88.0.0/16", "10.88.0.999");
  const mc::Expected<std::string> ip = mc::allocate_ip(net, {});
  ASSERT_FALSE(ip.has_value());
  EXPECT_EQ(ip.error().op(), mc::Op::ConfigureAddress);
}

TEST(IpAllocationTest, UnparseableTakenEntryIsSkippedNotFatal) {
  // A corrupt record for one container must not block starting another; the
  // cost is that the corrupt entry's address is not reserved, which is the
  // lesser of the two failures.
  const mc::NetworkConfig net = net_with("10.88.0.0/16", "10.88.0.1");
  const mc::Expected<std::string> ip =
      mc::allocate_ip(net, {"garbage", "10.88.0.2"});
  ASSERT_TRUE(ip.has_value()) << ip.error().message();
  EXPECT_EQ(*ip, "10.88.0.3/16");
}

TEST(IpAllocationTest, TakenAddressesOutsideTheSubnetDoNotShiftAllocation) {
  const mc::NetworkConfig net = net_with("10.88.0.0/16", "10.88.0.1");
  const mc::Expected<std::string> ip =
      mc::allocate_ip(net, {"192.168.1.2", "172.17.0.2"});
  ASSERT_TRUE(ip.has_value()) << ip.error().message();
  EXPECT_EQ(*ip, "10.88.0.2/16");
}

// ---------------------------------------------------------------------------
// parse_ipv4
// ---------------------------------------------------------------------------
TEST(NetIpv4ParseTest, ValidDottedQuads) {
  EXPECT_EQ(addr("0.0.0.0"), 0u);
  EXPECT_EQ(addr("255.255.255.255"), 0xFFFFFFFFu);
  EXPECT_EQ(addr("10.88.0.1"), 0x0A580001u);
  EXPECT_EQ(addr("192.168.1.254"), 0xC0A801FEu);
  EXPECT_EQ(addr("127.0.0.1"), 0x7F000001u);
}

TEST(NetIpv4ParseTest, RejectsOctetAbove255) {
  EXPECT_FALSE(parse_ipv4("10.88.0.256", kOp).has_value());
  EXPECT_FALSE(parse_ipv4("256.0.0.1", kOp).has_value());
  // Three digits is the maximum an octet may have, so 1000 is rejected on
  // length before it can overflow the accumulator.
  EXPECT_FALSE(parse_ipv4("1000.0.0.1", kOp).has_value());
}

TEST(NetIpv4ParseTest, RejectsWrongNumberOfOctets) {
  EXPECT_FALSE(parse_ipv4("10.88.0", kOp).has_value());
  EXPECT_FALSE(parse_ipv4("10.88", kOp).has_value());
  EXPECT_FALSE(parse_ipv4("10", kOp).has_value());
  EXPECT_FALSE(parse_ipv4("10.88.0.1.2", kOp).has_value());
  EXPECT_FALSE(parse_ipv4("10.88.0.", kOp).has_value());
  EXPECT_FALSE(parse_ipv4(".88.0.1", kOp).has_value());
  EXPECT_FALSE(parse_ipv4("", kOp).has_value());
}

TEST(NetIpv4ParseTest, RejectsWhatInetAtonWouldQuietlyAccept) {
  // The reason this parser is hand-rolled: inet_aton() accepts all of these
  // and turns them into addresses the user did not write. A container runtime
  // that quietly hands out a different address than the one configured is
  // worse than one that refuses a typo.
  EXPECT_FALSE(parse_ipv4("0x0a580001", kOp).has_value());
  EXPECT_FALSE(parse_ipv4("10.88.1", kOp).has_value());
  EXPECT_FALSE(parse_ipv4(" 10.88.0.1", kOp).has_value());
  EXPECT_FALSE(parse_ipv4("10.88.0.1 ", kOp).has_value());
  EXPECT_FALSE(parse_ipv4("10.88.0.-1", kOp).has_value());
  EXPECT_FALSE(parse_ipv4("10.88.0.+1", kOp).has_value());
}

TEST(NetIpv4ParseTest, LeadingZeroesAreDecimalNotOctal) {
  // inet_aton() reads "088" as octal - and 088 is not even valid octal. Here
  // it is plain decimal, so "10.088.0.1" is the same address as "10.88.0.1"
  // rather than a silently different one.
  EXPECT_EQ(addr("10.088.0.1"), addr("10.88.0.1"));
  EXPECT_EQ(addr("010.088.000.001"), addr("10.88.0.1"));
}

TEST(NetIpv4ParseTest, ErrorCarriesTheOpAndTheOffendingText) {
  const mc::Expected<std::uint32_t> r =
      parse_ipv4("10.88.0.999", mc::Op::CreateBridge);
  ASSERT_FALSE(r.has_value());
  EXPECT_EQ(r.error().op(), mc::Op::CreateBridge);
  EXPECT_NE(r.error().message().find("10.88.0.999"), std::string::npos);
}

// ---------------------------------------------------------------------------
// parse_ipv4_cidr
// ---------------------------------------------------------------------------
TEST(NetCidrParseTest, ClearsHostBits) {
  // The documented contract: Ipv4Cidr::network has host bits already cleared,
  // so callers can compare `address & mask == network` without re-masking.
  const mc::Expected<Ipv4Cidr> r = parse_ipv4_cidr("10.88.5.7/16", kOp);
  ASSERT_TRUE(r.has_value()) << r.error().message();
  EXPECT_EQ(r->prefix, 16);
  EXPECT_EQ(r->network, addr("10.88.0.0"));
}

TEST(NetCidrParseTest, PrefixBoundaries) {
  const mc::Expected<Ipv4Cidr> zero = parse_ipv4_cidr("10.88.5.7/0", kOp);
  ASSERT_TRUE(zero.has_value());
  EXPECT_EQ(zero->prefix, 0);
  // /0 masks everything away. Special-cased in the parser because shifting a
  // 32-bit value by 32 is undefined behaviour.
  EXPECT_EQ(zero->network, 0u);

  const mc::Expected<Ipv4Cidr> full = parse_ipv4_cidr("10.88.5.7/32", kOp);
  ASSERT_TRUE(full.has_value());
  EXPECT_EQ(full->prefix, 32);
  EXPECT_EQ(full->network, addr("10.88.5.7"));

  const mc::Expected<Ipv4Cidr> slash24 = parse_ipv4_cidr("10.88.5.7/24", kOp);
  ASSERT_TRUE(slash24.has_value());
  EXPECT_EQ(slash24->network, addr("10.88.5.0"));
}

TEST(NetCidrParseTest, RejectsPrefixAbove32) {
  EXPECT_FALSE(parse_ipv4_cidr("10.88.0.0/33", kOp).has_value());
  EXPECT_FALSE(parse_ipv4_cidr("10.88.0.0/64", kOp).has_value());
  EXPECT_FALSE(parse_ipv4_cidr("10.88.0.0/999", kOp).has_value());
  EXPECT_FALSE(parse_ipv4_cidr("10.88.0.0/-1", kOp).has_value());
  EXPECT_FALSE(parse_ipv4_cidr("10.88.0.0/", kOp).has_value());
}

TEST(NetCidrParseTest, RejectsMissingSlashAndBadAddress) {
  const mc::Expected<Ipv4Cidr> no_slash = parse_ipv4_cidr("10.88.0.0", kOp);
  ASSERT_FALSE(no_slash.has_value());
  EXPECT_NE(no_slash.error().message().find("missing /prefix"),
            std::string::npos);

  EXPECT_FALSE(parse_ipv4_cidr("10.88.0.256/16", kOp).has_value());
  EXPECT_FALSE(parse_ipv4_cidr("/16", kOp).has_value());
  EXPECT_FALSE(parse_ipv4_cidr("", kOp).has_value());
}

// ---------------------------------------------------------------------------
// format_ipv4 / format_cidr
// ---------------------------------------------------------------------------
TEST(NetFormatTest, FormatIpv4RoundTripsWithParseIpv4) {
  for (const char* text : {"0.0.0.0", "10.88.0.1", "192.168.1.254",
                           "172.17.0.2", "255.255.255.255"}) {
    const std::uint32_t value = addr(text);
    EXPECT_EQ(format_ipv4(value), text);
    EXPECT_EQ(addr(format_ipv4(value).c_str()), value);
  }
}

TEST(NetFormatTest, FormatCidrRoundTripsWithParseIpv4Cidr) {
  for (const char* text :
       {"10.88.0.0/16", "192.168.5.0/24", "0.0.0.0/0", "10.88.5.7/32"}) {
    const mc::Expected<Ipv4Cidr> parsed = parse_ipv4_cidr(text, kOp);
    ASSERT_TRUE(parsed.has_value()) << text;
    EXPECT_EQ(format_cidr(*parsed), text);

    const mc::Expected<Ipv4Cidr> again =
        parse_ipv4_cidr(format_cidr(*parsed), kOp);
    ASSERT_TRUE(again.has_value());
    EXPECT_EQ(again->network, parsed->network);
    EXPECT_EQ(again->prefix, parsed->prefix);
  }
}

TEST(NetFormatTest, FormatCidrNormalisesHostBitsAway) {
  // format_cidr(parse_ipv4_cidr(x)) is the canonical spelling of x's network,
  // which is what error messages such as "gateway ... is not inside ..."
  // print.
  const mc::Expected<Ipv4Cidr> parsed = parse_ipv4_cidr("10.88.5.7/16", kOp);
  ASSERT_TRUE(parsed.has_value());
  EXPECT_EQ(format_cidr(*parsed), "10.88.0.0/16");
}

// ---------------------------------------------------------------------------
// validate_ifname
//
// Checked before every `ip` invocation, so a malformed name fails here with a
// message naming the real problem instead of as an opaque iproute2 usage
// error - or, worse, as an option the shell-free execvp still passes through.
// ---------------------------------------------------------------------------
TEST(NetIfnameTest, AcceptsOrdinaryNames) {
  EXPECT_TRUE(validate_ifname("eth0", kOp).has_value());
  EXPECT_TRUE(validate_ifname("mc-br0", kOp).has_value());
  EXPECT_TRUE(validate_ifname("mc-a1b2c3d4", kOp).has_value());
  EXPECT_TRUE(validate_ifname("veth_0.1", kOp).has_value());
  // Exactly IFNAMSIZ-1 = 15 bytes is the longest the kernel accepts.
  EXPECT_TRUE(validate_ifname("abcdefghijklmno", kOp).has_value());
}

TEST(NetIfnameTest, RejectsNamesLongerThanIfnamsizMinusOne) {
  const std::string too_long(16, 'a');  // IFNAMSIZ-1 is 15
  const mc::Expected<void> r = validate_ifname(too_long, kOp);
  ASSERT_FALSE(r.has_value());
  EXPECT_EQ(r.error().op(), kOp);
  EXPECT_NE(r.error().message().find("15-byte limit"), std::string::npos);

  EXPECT_FALSE(validate_ifname(std::string(64, 'a'), kOp).has_value());
}

TEST(NetIfnameTest, RejectsSlash) {
  // '/' would let a name escape into a path, and the kernel refuses it
  // anyway; catching it here names the real problem.
  const mc::Expected<void> r = validate_ifname("mc/br0", kOp);
  ASSERT_FALSE(r.has_value());
  EXPECT_NE(r.error().message().find("illegal character"), std::string::npos);

  EXPECT_FALSE(validate_ifname("../../etc/passwd", kOp).has_value());
}

TEST(NetIfnameTest, RejectsWhitespace) {
  // A space would split into two argv entries in any shell-based design; this
  // one has no shell, so instead `ip` would see a single odd name. Either way
  // it is not a valid interface name.
  EXPECT_FALSE(validate_ifname("mc br0", kOp).has_value());
  EXPECT_FALSE(validate_ifname(" eth0", kOp).has_value());
  EXPECT_FALSE(validate_ifname("eth0 ", kOp).has_value());
  EXPECT_FALSE(validate_ifname("eth\t0", kOp).has_value());
  EXPECT_FALSE(validate_ifname("eth\n0", kOp).has_value());
}

TEST(NetIfnameTest, RejectsEmptyReservedAndOptionLookalikes) {
  EXPECT_FALSE(validate_ifname("", kOp).has_value());
  EXPECT_FALSE(validate_ifname(".", kOp).has_value());
  EXPECT_FALSE(validate_ifname("..", kOp).has_value());
  // execvp has no shell to strip a leading '-', so `ip link add -foo` would
  // read it as a flag: option injection, the one gap argv arrays leave open.
  const mc::Expected<void> dash = validate_ifname("-foo", kOp);
  ASSERT_FALSE(dash.has_value());
  EXPECT_NE(dash.error().message().find("command option"), std::string::npos);
}

// ---------------------------------------------------------------------------
// osrelease_indicates_wsl
//
// Split out of running_under_wsl() precisely so it can be tested against a
// supplied string rather than whatever host the suite happens to run on.
// ---------------------------------------------------------------------------
TEST(NetWslTest, MatchesMicrosoftInAnyCase) {
  EXPECT_TRUE(osrelease_indicates_wsl("5.15.167.4-microsoft-standard-WSL2"));
  // WSL1 spelled it with a capital M.
  EXPECT_TRUE(osrelease_indicates_wsl("4.4.0-19041-Microsoft"));
  EXPECT_TRUE(osrelease_indicates_wsl("MICROSOFT"));
  EXPECT_TRUE(osrelease_indicates_wsl("mIcRoSoFt"));
  // The needle may sit at either end of the string.
  EXPECT_TRUE(osrelease_indicates_wsl("microsoft"));
  EXPECT_TRUE(osrelease_indicates_wsl("6.6.0-generic-microsoft"));
}

TEST(NetWslTest, DoesNotMatchAnOrdinaryLinuxRelease) {
  EXPECT_FALSE(osrelease_indicates_wsl("6.8.0-45-generic"));
  EXPECT_FALSE(osrelease_indicates_wsl("5.15.0-91-generic"));
  EXPECT_FALSE(osrelease_indicates_wsl("6.1.0-18-amd64"));
  EXPECT_FALSE(osrelease_indicates_wsl("4.18.0-513.el8.x86_64"));
}

TEST(NetWslTest, HandlesShortAndEmptyStrings) {
  // The scan must not read past the end when the string is shorter than the
  // needle - the reason for the explicit size check ahead of the loop.
  EXPECT_FALSE(osrelease_indicates_wsl(""));
  EXPECT_FALSE(osrelease_indicates_wsl("m"));
  EXPECT_FALSE(osrelease_indicates_wsl("microsof"));
  EXPECT_TRUE(osrelease_indicates_wsl("microsoft"));
}
