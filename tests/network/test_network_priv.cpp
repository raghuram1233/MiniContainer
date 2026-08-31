// SPDX-License-Identifier: MIT
//
// MiniContainer - networking PRIVILEGED integration tests.
//
// These talk to the real kernel: they create a real bridge, a real veth pair,
// move one end into a real network namespace via a real clone3()'d process,
// and configure it with the same raw ioctls step_configure_address uses in
// production. Labelled "root" by tests/CMakeLists.txt, so `ctest -LE root`
// skips the whole binary.
//
// WHY THIS FILE EXISTS
// --------------------
// Bridge networking compiled and had unit coverage for its pure logic (CIDR
// parsing, address allocation, interface-name validation) for a long time
// before it was ever actually run. The first real run found a genuine bug:
// create_veth_pair named the container-side peer literally "eth0", but both
// ends of a veth pair briefly exist in the HOST namespace during creation -
// and "eth0" is exactly the name a real host is likely to already have (a
// WSL2 VM's own adapter, a cloud VM's primary NIC). Creating an interface
// under that name then failed with EEXIST on any such host, which is most of
// them. This file is what would have caught that before a human had to.
//
// HOST SAFETY
// -----------
// Every test uses a scratch bridge name ("mc-test-<pid>"), never the real
// "mc-br0", so a test run cannot disturb a bridge a developer's own
// containers are using. TearDown deletes every veth and the scratch bridge
// unconditionally - after a pass, a fail, or a fatal assertion.
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <memory>
#include <string>

#include "minicontainer/container.h"
#include "minicontainer/errors.h"
#include "minicontainer/network.h"
#include "minicontainer/process.h"

#include <gtest/gtest.h>
#include <netinet/in.h>

#define MC_REQUIRE_ROOT()              \
  do {                                 \
    if (::geteuid() != 0) {            \
      GTEST_SKIP() << "requires root"; \
    }                                  \
  } while (0)

namespace mc {
namespace {

// A plain-fork child (no namespaces of its own) whose only job is to block on
// a pipe, then run step_configure_address with a ChildContext the parent
// built before clone() - exactly the role container_child_main plays in
// production, minus everything unrelated to networking. clone_process's
// contract (process.h) forbids child_fn from allocating; everything this
// function touches was already allocated by the parent before clone().
struct NetChildArgs {
  ChildContext ctx;
  int sync_read_fd = -1;
  int result_write_fd = -1;
};

// Read back over the result pipe after the child configures its interface.
// A plain memcpy'able POD, matching the no-allocation constraint this whole
// path is built around.
struct NetChildResult {
  bool ok = false;
  int err = 0;
  char addr[32] = {};  // "10.99.0.7", read back via SIOCGIFADDR after rename
};

int net_child_fn(void* raw) noexcept {
  auto* a = static_cast<NetChildArgs*>(raw);

  char go = 0;
  if (::read(a->sync_read_fd, &go, 1) != 1 || go != 'G') {
    ::_exit(126);
  }

  NetChildResult result;
  const ChildStatus st = step_configure_address(a->ctx);
  result.ok = st.ok();
  result.err = st.err;

  if (st.ok()) {
    // Read the address back with a fresh ioctl rather than trusting what was
    // asked for - this is what actually proves the rename landed and the
    // kernel accepted the configuration, not just that no call returned an
    // error.
    const int sock = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (sock >= 0) {
      struct ::ifreq req {};
      std::strncpy(req.ifr_name, "eth0", IFNAMSIZ - 1);
      if (::ioctl(sock, SIOCGIFADDR, &req) == 0) {
        const char* ip = ::inet_ntoa(
            reinterpret_cast<struct ::sockaddr_in*>(&req.ifr_addr)->sin_addr);
        std::strncpy(result.addr, ip, sizeof(result.addr) - 1);
      }
      ::close(sock);
    }
  }

  (void)::write(a->result_write_fd, &result, sizeof(result));
  ::_exit(result.ok ? 0 : 1);
}

// Removes the scratch bridge created for one test. Never touches the real
// "mc-br0" - the name is always the caller's own unique scratch name. Silent
// on a missing bridge: not every test in this file creates one, and "nothing
// to delete" is an expected outcome of teardown, not something worth
// cluttering test output with.
void delete_bridge(const std::string& name) {
  const ::pid_t pid = ::fork();
  if (pid == 0) {
    const int devnull = ::open("/dev/null", O_WRONLY);
    if (devnull >= 0) {
      ::dup2(devnull, STDERR_FILENO);
    }
    ::execlp("ip", "ip", "link", "del", name.c_str(),
             static_cast<char*>(nullptr));
    ::_exit(127);
  }
  if (pid > 0) {
    int status = 0;
    ::waitpid(pid, &status, 0);
  }
}

class NetworkPriv : public ::testing::Test {
 protected:
  void SetUp() override {
    // Unique per test process, so two runs (or a run alongside a developer's
    // own containers) cannot collide on the bridge name.
    bridge_name_ = "mc-test-" + std::to_string(::getpid() % 100000);
  }

  void TearDown() override {
    if (!alloc_.veth_host.empty()) {
      (void)teardown_network(alloc_);
    }
    if (!bridge_name_.empty()) {
      delete_bridge(bridge_name_);
    }
  }

  std::string bridge_name_;
  NetworkAllocation alloc_;
};

}  // namespace

// ---------------------------------------------------------------------------
// This is the test that would have caught the eth0 collision: it runs the
// exact same public sequence launch_container does (ensure_bridge,
// create_veth_pair, attach_to_bridge, step_configure_address) against a real
// kernel, and reads the result back from inside the child's own network
// namespace rather than trusting a lack of errors.
// ---------------------------------------------------------------------------
TEST_F(NetworkPriv, FullBridgeSequenceConfiguresARealInterface) {
  MC_REQUIRE_ROOT();

  NetworkConfig net;
  net.mode = NetworkMode::Bridge;
  net.bridge_name = bridge_name_;
  net.subnet_cidr = "10.99.0.0/24";
  net.gateway_ip = "10.99.0.1";

  {
    Expected<void> ok = ensure_bridge(net);
    ASSERT_TRUE(ok) << ok.error().message();
  }

  alloc_.bridge = net.bridge_name;
  alloc_.gateway = net.gateway_ip;
  alloc_.veth_host = ("mc-" + std::to_string(::getpid())).substr(0, 15);
  alloc_.ip_cidr = "10.99.0.7/24";

  // The pipes the real handshake uses, minus everything unrelated to
  // networking - see process.h's three-pipe diagram.
  Expected<Pipe> sync_pipe = Pipe::create();
  ASSERT_TRUE(sync_pipe) << sync_pipe.error().message();
  Expected<Pipe> result_pipe = Pipe::create();
  ASSERT_TRUE(result_pipe) << result_pipe.error().message();

  auto args = std::make_unique<NetChildArgs>();
  args->sync_read_fd = sync_pipe->read_end.get();
  args->result_write_fd = result_pipe->write_end.get();
  args->ctx.configure_loopback = true;

  // Deliberately the SAME temporary name create_veth_pair will actually use -
  // this is exactly what launch.cpp does, and exactly the invariant that
  // broke when the two disagreed. arena is a plain fixed char buffer inside
  // ChildContext, so this is a direct copy, no pointer games needed.
  const std::string peer_name = veth_peer_temp_name(alloc_.veth_host);
  std::strncpy(args->ctx.arena, peer_name.c_str(), sizeof(args->ctx.arena) - 1);
  args->ctx.veth_name = args->ctx.arena;
  args->ctx.container_ip_cidr = alloc_.ip_cidr.c_str();
  args->ctx.gateway_ip = alloc_.gateway.c_str();

  CloneRequest req;
  req.flags = CLONE_NEWNET;
  req.exit_signal = SIGCHLD;
  Expected<CloneResult> cloned = clone_process(req, &net_child_fn, args.get());
  ASSERT_TRUE(cloned) << cloned.error().message();

  // Everything below mirrors launch_container's own sequence for bridge mode.
  {
    Expected<void> ok = create_veth_pair(alloc_, cloned->pid);
    ASSERT_TRUE(ok) << ok.error().message();
  }
  {
    Expected<void> ok = attach_to_bridge(alloc_);
    ASSERT_TRUE(ok) << ok.error().message();
  }

  ASSERT_TRUE(sync_pipe->write_byte('G'));
  sync_pipe->write_end.reset();

  NetChildResult result{};
  const ssize_t n =
      ::read(result_pipe->read_end.get(), &result, sizeof(result));
  ASSERT_EQ(n, static_cast<ssize_t>(sizeof(result)));

  int status = 0;
  ::waitpid(cloned->pid, &status, 0);

  EXPECT_TRUE(result.ok) << "step_configure_address failed with errno "
                         << result.err << " (" << std::strerror(result.err)
                         << ") - this is the exact failure mode the eth0 "
                            "collision bug produced";
  EXPECT_STREQ(result.addr, "10.99.0.7")
      << "the address read back from inside the child's own netns, after the "
         "rename to eth0, must match what was configured - a mismatch means "
         "the rename or the address assignment silently landed on the wrong "
         "interface";
}

// ---------------------------------------------------------------------------
// The narrower regression: create_veth_pair must succeed even when this host
// already has a real "eth0" - which is exactly the scenario the original bug
// failed on, and WSL2 (this project's own development environment) always
// has one.
// ---------------------------------------------------------------------------
TEST_F(NetworkPriv, PeerNameNeverCollidesWithARealHostInterface) {
  MC_REQUIRE_ROOT();

  const std::string peer = veth_peer_temp_name("mc-abc123456789");
  EXPECT_NE(peer, "eth0");

  NetworkAllocation alloc;
  alloc.veth_host = ("mc-" + std::to_string(::getpid())).substr(0, 15);
  alloc.veth_container = "eth0";

  Expected<CloneResult> cloned = clone_process(
      CloneRequest{CLONE_NEWNET, SIGCHLD, -1},
      +[](void*) noexcept -> int {
        ::pause();
        return 0;
      },
      nullptr);
  ASSERT_TRUE(cloned) << cloned.error().message();

  Expected<void> created = create_veth_pair(alloc, cloned->pid);
  EXPECT_TRUE(created) << created.error().message();

  ::kill(cloned->pid, SIGKILL);
  int status = 0;
  ::waitpid(cloned->pid, &status, 0);

  if (created) {
    alloc_ = alloc;  // let TearDown clean up the host-side end
  }
}

}  // namespace mc
