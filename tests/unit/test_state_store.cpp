// SPDX-License-Identifier: MIT
//
// Unit tests for src/runtime/state_store.cpp - ContainerState serialisation
// and the on-disk StateStore. Run without root.
//
// WHY THESE TESTS ARE UNPRIVILEGED AND SANDBOXED
// ----------------------------------------------
// Every test here runs against a mkdtemp'd directory under /tmp with
// RuntimePaths::state_root pointed at it. Nothing in this file may ever touch
// /var/lib/minicontainer: doing so would read - and with remove(), destroy -
// the records of the machine's real containers, whose cgroups and veths are
// only findable through those files.
//
// WHAT IS ACTUALLY BEING PROTECTED
// --------------------------------
//   * A full round-trip loses nothing. state.json is the only record that
//     survives the launching process, so a field dropped here is a resource
//     that can never be cleaned up.
//   * An unset std::optional stays unset AND stays absent from the file.
//     Round-tripping an unset memory limit as 0 would turn "no limit" into
//     "zero bytes", which the kernel enforces by killing the container
//     instantly.
//   * list() survives one corrupt record. A single bad file must not make
//     `ps` useless for every other container on the host.
//   * is_alive() rejects a pid whose start time does not match. Pids are
//     recycled; without this check a stale record would let us report - or
//     signal - a completely unrelated process. This is the single most
//     important behaviour in the file.

#include <sys/stat.h>
#include <sys/types.h>

#include <dirent.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "minicontainer/config.h"
#include "minicontainer/errors.h"
#include "minicontainer/json.h"
#include "minicontainer/runtime.h"
#include "minicontainer/syscall.h"

#include <gtest/gtest.h>

namespace mc {
namespace {

// Recursive delete confined to the fixture's own /tmp directory.
void RemoveTree(const std::string& path) {
  DIR* dir = ::opendir(path.c_str());
  if (dir == nullptr) {
    ::unlink(path.c_str());
    return;
  }
  while (dirent* entry = ::readdir(dir)) {
    const std::string name = entry->d_name;
    if (name == "." || name == "..")
      continue;
    const std::string child = path + "/" + name;
    struct stat st {};
    if (::lstat(child.c_str(), &st) < 0)
      continue;
    if (S_ISDIR(st.st_mode)) {
      RemoveTree(child);
    } else {
      ::unlink(child.c_str());
    }
  }
  ::closedir(dir);
  ::rmdir(path.c_str());
}

bool WriteRaw(const std::string& path, const std::string& text) {
  std::FILE* f = std::fopen(path.c_str(), "wb");
  if (f == nullptr)
    return false;
  const bool ok = std::fwrite(text.data(), 1, text.size(), f) == text.size();
  std::fclose(f);
  return ok;
}

class StateStoreTest : public ::testing::Test {
 protected:
  void SetUp() override {
    char tmpl[] = "/tmp/mc-state-test-XXXXXX";
    const char* dir = ::mkdtemp(tmpl);
    ASSERT_NE(dir, nullptr) << "mkdtemp: " << std::strerror(errno);
    root_ = dir;
    // The guard the whole file depends on: if this ever became the real root,
    // remove() below would delete a live host's container records.
    ASSERT_NE(root_, "/var/lib/minicontainer");
    ASSERT_EQ(root_.rfind("/tmp/", 0), 0u);

    paths_.state_root = root_;
    store_ = std::make_unique<StateStore>(paths_);
  }

  void TearDown() override {
    store_.reset();
    if (!root_.empty())
      RemoveTree(root_);
  }

  // A minimal but valid record: save() only insists on a non-empty id.
  static ContainerState Minimal(const std::string& id,
                                const std::string& name = {}) {
    ContainerState s;
    s.id = id;
    s.name = name;
    s.created_at = "2026-08-30T12:34:56.789Z";
    s.config.id = id;
    s.config.name = name;
    return s;
  }

  std::string root_;
  RuntimePaths paths_;
  std::unique_ptr<StateStore> store_;
};

// Every field set to something distinguishable from its default, so a field
// that silently fails to serialise shows up as a mismatch rather than as a
// coincidentally-equal default.
ContainerState FullyPopulated() {
  ContainerState s;
  s.id = "a1b2c3d4e5f6";
  s.name = "web";
  s.status = ContainerStatus::Running;
  s.pid = 4242;
  s.pid_start_time = 987654321u;
  s.created_at = "2026-08-30T12:34:56.789Z";
  s.started_at = "2026-08-30T12:34:57.001Z";
  s.finished_at = "2026-08-30T13:00:00.500Z";
  s.exit_code = 137;
  s.term_signal = 9;
  s.cgroup_path = "/sys/fs/cgroup/minicontainer/a1b2c3d4e5f6";

  s.network.veth_host = "mc-a1b2c3d4";
  s.network.veth_container = "eth0";
  s.network.ip_cidr = "10.88.0.7/16";
  s.network.gateway = "10.88.0.1";
  s.network.bridge = "mc-br0";
  s.network.nat_configured = true;
  s.network.published.push_back(PortMapping{8080, 80, "tcp"});
  s.network.published.push_back(PortMapping{5353, 53, "udp"});

  ContainerConfig& c = s.config;
  c.id = s.id;
  c.name = s.name;
  c.hostname = "web-host";
  c.rootfs_path = "/var/lib/minicontainer/rootfs/alpine";
  c.args = {"/bin/sh", "-c", "echo hello \"world\""};
  c.env = {"PATH=/usr/bin:/bin", "LANG=C.UTF-8", "MSG=a\tb"};
  c.working_dir = "/srv/app";
  c.bind_mounts = {"/host/data:/data", "/host/etc:/etc/app:ro"};
  c.tty = true;
  c.detach = true;
  c.remove_on_exit = true;

  c.resources.memory_bytes = 268435456u;
  c.resources.memory_swap_bytes = 536870912u;
  c.resources.cpus = 1.5;
  c.resources.cpu_shares = 512u;
  c.resources.pids_max = 100u;
  c.resources.cpuset_cpus = "0-3";

  c.network.mode = NetworkMode::Bridge;
  c.network.bridge_name = "mc-br1";
  c.network.subnet_cidr = "10.99.0.0/16";
  c.network.gateway_ip = "10.99.0.1";
  c.network.container_ip = "10.99.0.7";
  c.network.dns_servers = {"9.9.9.9", "1.0.0.1"};
  c.network.ports = {PortMapping{8080, 80, "tcp"},
                     PortMapping{5353, 53, "udp"}};
  c.network.enable_nat = false;

  c.security.cap_drop = {"ALL", "CAP_NET_RAW"};
  c.security.cap_add = {"CAP_NET_BIND_SERVICE"};
  c.security.seccomp = SeccompMode::Profile;
  c.security.seccomp_profile_path = "/etc/minicontainer/seccomp.json";
  c.security.no_new_privs = false;
  c.security.userns = true;
  c.security.userns_host_uid = 100000;
  c.security.userns_host_gid = 100001;
  c.security.userns_size = 65535;
  c.security.privileged = true;
  c.security.readonly_rootfs = true;
  return s;
}

// ---------------------------------------------------------------------------
// ContainerState round-trip: every field, asserted individually.
// ---------------------------------------------------------------------------
TEST(ContainerStateJsonTest, FullyPopulatedRoundTrip) {
  const ContainerState in = FullyPopulated();
  Expected<ContainerState> parsed = ContainerState::from_json(in.to_json());
  ASSERT_TRUE(parsed.has_value()) << parsed.error().message();
  const ContainerState& out = *parsed;

  EXPECT_EQ(out.id, in.id);
  EXPECT_EQ(out.name, in.name);
  EXPECT_EQ(out.status, ContainerStatus::Running);
  EXPECT_EQ(out.pid, in.pid);
  EXPECT_EQ(out.pid_start_time, in.pid_start_time);
  EXPECT_EQ(out.created_at, in.created_at);
  EXPECT_EQ(out.started_at, in.started_at);
  EXPECT_EQ(out.finished_at, in.finished_at);
  EXPECT_EQ(out.exit_code, in.exit_code);
  EXPECT_EQ(out.term_signal, in.term_signal);
  EXPECT_EQ(out.cgroup_path, in.cgroup_path);

  // NetworkAllocation: this is the record teardown uses to know exactly which
  // interfaces and rules are ours to remove.
  EXPECT_EQ(out.network.veth_host, in.network.veth_host);
  EXPECT_EQ(out.network.veth_container, in.network.veth_container);
  EXPECT_EQ(out.network.ip_cidr, in.network.ip_cidr);
  EXPECT_EQ(out.network.gateway, in.network.gateway);
  EXPECT_EQ(out.network.bridge, in.network.bridge);
  EXPECT_EQ(out.network.nat_configured, in.network.nat_configured);
  ASSERT_EQ(out.network.published.size(), 2u);
  EXPECT_EQ(out.network.published[0].host_port, 8080);
  EXPECT_EQ(out.network.published[0].container_port, 80);
  EXPECT_EQ(out.network.published[0].protocol, "tcp");
  EXPECT_EQ(out.network.published[1].host_port, 5353);
  EXPECT_EQ(out.network.published[1].container_port, 53);
  EXPECT_EQ(out.network.published[1].protocol, "udp");

  const ContainerConfig& a = in.config;
  const ContainerConfig& b = out.config;
  EXPECT_EQ(b.id, a.id);
  EXPECT_EQ(b.name, a.name);
  EXPECT_EQ(b.hostname, a.hostname);
  EXPECT_EQ(b.rootfs_path, a.rootfs_path);
  EXPECT_EQ(b.args, a.args);
  EXPECT_EQ(b.env, a.env);
  EXPECT_EQ(b.working_dir, a.working_dir);
  EXPECT_EQ(b.bind_mounts, a.bind_mounts);
  EXPECT_EQ(b.tty, a.tty);
  EXPECT_EQ(b.detach, a.detach);
  EXPECT_EQ(b.remove_on_exit, a.remove_on_exit);

  ASSERT_TRUE(b.resources.memory_bytes.has_value());
  EXPECT_EQ(*b.resources.memory_bytes, 268435456u);
  ASSERT_TRUE(b.resources.memory_swap_bytes.has_value());
  EXPECT_EQ(*b.resources.memory_swap_bytes, 536870912u);
  ASSERT_TRUE(b.resources.cpus.has_value());
  EXPECT_DOUBLE_EQ(*b.resources.cpus, 1.5);
  ASSERT_TRUE(b.resources.cpu_shares.has_value());
  EXPECT_EQ(*b.resources.cpu_shares, 512u);
  ASSERT_TRUE(b.resources.pids_max.has_value());
  EXPECT_EQ(*b.resources.pids_max, 100u);
  ASSERT_TRUE(b.resources.cpuset_cpus.has_value());
  EXPECT_EQ(*b.resources.cpuset_cpus, "0-3");

  EXPECT_EQ(b.network.mode, NetworkMode::Bridge);
  EXPECT_EQ(b.network.bridge_name, a.network.bridge_name);
  EXPECT_EQ(b.network.subnet_cidr, a.network.subnet_cidr);
  EXPECT_EQ(b.network.gateway_ip, a.network.gateway_ip);
  ASSERT_TRUE(b.network.container_ip.has_value());
  EXPECT_EQ(*b.network.container_ip, "10.99.0.7");
  EXPECT_EQ(b.network.dns_servers, a.network.dns_servers);
  ASSERT_EQ(b.network.ports.size(), 2u);
  EXPECT_EQ(b.network.ports[0].host_port, 8080);
  EXPECT_EQ(b.network.ports[0].container_port, 80);
  EXPECT_EQ(b.network.ports[0].protocol, "tcp");
  EXPECT_EQ(b.network.ports[1].host_port, 5353);
  EXPECT_EQ(b.network.ports[1].container_port, 53);
  EXPECT_EQ(b.network.ports[1].protocol, "udp");
  EXPECT_EQ(b.network.enable_nat, false);

  EXPECT_EQ(b.security.cap_drop, a.security.cap_drop);
  EXPECT_EQ(b.security.cap_add, a.security.cap_add);
  EXPECT_EQ(b.security.seccomp, SeccompMode::Profile);
  EXPECT_EQ(b.security.seccomp_profile_path, a.security.seccomp_profile_path);
  EXPECT_EQ(b.security.no_new_privs, false);
  EXPECT_EQ(b.security.userns, true);
  EXPECT_EQ(b.security.userns_host_uid, 100000u);
  EXPECT_EQ(b.security.userns_host_gid, 100001u);
  EXPECT_EQ(b.security.userns_size, 65535u);
  EXPECT_EQ(b.security.privileged, true);
  EXPECT_EQ(b.security.readonly_rootfs, true);

  // Serialising the reconstructed record must produce identical bytes;
  // anything else means a field survived one direction but not the other.
  EXPECT_EQ(out.to_json().dump(2), in.to_json().dump(2));
}

TEST(ContainerStateJsonTest, EveryStatusRoundTrips) {
  for (ContainerStatus st : {ContainerStatus::Created, ContainerStatus::Running,
                             ContainerStatus::Stopped}) {
    ContainerState s;
    s.id = "id0000000001";
    s.status = st;
    Expected<ContainerState> back = ContainerState::from_json(s.to_json());
    ASSERT_TRUE(back.has_value()) << back.error().message();
    EXPECT_EQ(back->status, st) << container_status_name(st);
  }
}

TEST(ContainerStateJsonTest, EverySeccompModeRoundTrips) {
  for (SeccompMode m :
       {SeccompMode::Off, SeccompMode::Default, SeccompMode::Profile}) {
    ContainerState s;
    s.id = "id0000000002";
    s.config.security.seccomp = m;
    Expected<ContainerState> back = ContainerState::from_json(s.to_json());
    ASSERT_TRUE(back.has_value()) << back.error().message();
    EXPECT_EQ(back->config.security.seccomp, m);
  }
}

TEST(ContainerStateJsonTest, EveryNetworkModeRoundTrips) {
  for (NetworkMode m :
       {NetworkMode::None, NetworkMode::Bridge, NetworkMode::Host}) {
    ContainerState s;
    s.id = "id0000000003";
    s.config.network.mode = m;
    Expected<ContainerState> back = ContainerState::from_json(s.to_json());
    ASSERT_TRUE(back.has_value()) << back.error().message();
    EXPECT_EQ(back->config.network.mode, m) << network_mode_name(m);
  }
}

TEST(ContainerStateJsonTest, ExplicitlyEmptyDnsListSurvives) {
  // NetworkConfig::dns_servers defaults to two entries. An empty list means
  // the user asked for no DNS servers at all, and reviving the defaults on
  // read would silently give the container resolvers it was denied.
  ContainerState s;
  s.id = "id0000000004";
  s.config.network.dns_servers.clear();
  Expected<ContainerState> back = ContainerState::from_json(s.to_json());
  ASSERT_TRUE(back.has_value()) << back.error().message();
  EXPECT_TRUE(back->config.network.dns_servers.empty());
}

TEST(ContainerStateJsonTest, MissingIdIsRejected) {
  // Refusing a file with no id is what stops an unrelated JSON document that
  // happens to live at state.json from being adopted as a container record.
  Json j(JsonObject{});
  Expected<ContainerState> r = ContainerState::from_json(j);
  EXPECT_FALSE(r.has_value());

  Json not_object(std::string("nope"));
  EXPECT_FALSE(ContainerState::from_json(not_object).has_value());

  Json empty_id;
  empty_id.object()["id"] = Json("");
  EXPECT_FALSE(ContainerState::from_json(empty_id).has_value());
}

TEST(ContainerStateJsonTest, PartialRecordDegradesToDefaultsRatherThanFailing) {
  // A record written by an older version has fewer keys. It must still load,
  // because it is the only pointer to a cgroup that still needs removing.
  Json j;
  j.object()["id"] = Json("id0000000005");
  Expected<ContainerState> r = ContainerState::from_json(j);
  ASSERT_TRUE(r.has_value()) << r.error().message();
  EXPECT_EQ(r->id, "id0000000005");
  EXPECT_EQ(r->name, "");
  EXPECT_EQ(r->status, ContainerStatus::Created);
  // An absent pid reads back as -1, not 0: pid 0 is a real pid to kill(2).
  EXPECT_EQ(r->pid, -1);
  EXPECT_EQ(r->pid_start_time, 0u);
  EXPECT_FALSE(r->config.resources.memory_bytes.has_value());
}

// ---------------------------------------------------------------------------
// The optionals. This is the part that would be dangerous to get wrong.
// ---------------------------------------------------------------------------
TEST(ContainerStateJsonTest, UnsetResourceOptionalsAreAbsentFromTheJson) {
  ContainerState s;
  s.id = "id0000000006";
  s.config.resources.memory_bytes = 134217728u;  // set
  s.config.resources.pids_max = 64u;             // set
  // memory_swap_bytes, cpus, cpu_shares and cpuset_cpus deliberately unset.

  const Json j = s.to_json();
  const Json& res = j["config"]["resources"];
  ASSERT_EQ(res.type(), Json::Type::Object);

  EXPECT_TRUE(res.contains("memory_bytes"));
  EXPECT_TRUE(res.contains("pids_max"));
  // Absent, not null and not 0. memory.max = 0 is a limit the kernel will
  // enforce by OOM-killing the container the instant it starts; "no limit"
  // has to be spelled by the key simply not being there.
  EXPECT_FALSE(res.contains("memory_swap_bytes"));
  EXPECT_FALSE(res.contains("cpus"));
  EXPECT_FALSE(res.contains("cpu_shares"));
  EXPECT_FALSE(res.contains("cpuset_cpus"));

  // And nothing anywhere in the rendered file mentions them either, which
  // catches a stray write outside resources_to_json.
  const std::string text = j.dump(2);
  EXPECT_EQ(text.find("memory_swap_bytes"), std::string::npos) << text;
  EXPECT_EQ(text.find("cpu_shares"), std::string::npos) << text;
  EXPECT_EQ(text.find("cpuset_cpus"), std::string::npos) << text;
  EXPECT_EQ(text.find("\"cpus\""), std::string::npos) << text;
}

TEST(ContainerStateJsonTest, UnsetResourceOptionalsStayNulloptAfterRoundTrip) {
  ContainerState s;
  s.id = "id0000000007";
  s.config.resources.memory_bytes = 134217728u;
  s.config.resources.pids_max = 64u;

  Expected<ContainerState> back = ContainerState::from_json(s.to_json());
  ASSERT_TRUE(back.has_value()) << back.error().message();
  const Resources& r = back->config.resources;

  ASSERT_TRUE(r.memory_bytes.has_value());
  EXPECT_EQ(*r.memory_bytes, 134217728u);
  ASSERT_TRUE(r.pids_max.has_value());
  EXPECT_EQ(*r.pids_max, 64u);

  EXPECT_EQ(r.memory_swap_bytes, std::nullopt);
  EXPECT_EQ(r.cpus, std::nullopt);
  EXPECT_EQ(r.cpu_shares, std::nullopt);
  EXPECT_EQ(r.cpuset_cpus, std::nullopt);
}

TEST(ContainerStateJsonTest, AZeroLimitIsDistinctFromAnUnsetOne) {
  // The pair of assertions that makes the distinction observable: an
  // explicitly-zero limit must persist as 0, and an unset one must persist as
  // nothing. If either collapsed into the other the difference would be lost.
  ContainerState zero;
  zero.id = "id0000000008";
  zero.config.resources.memory_bytes = 0u;
  const Json jz = zero.to_json();
  EXPECT_TRUE(jz["config"]["resources"].contains("memory_bytes"));
  Expected<ContainerState> back_zero = ContainerState::from_json(jz);
  ASSERT_TRUE(back_zero.has_value()) << back_zero.error().message();
  ASSERT_TRUE(back_zero->config.resources.memory_bytes.has_value());
  EXPECT_EQ(*back_zero->config.resources.memory_bytes, 0u);

  ContainerState unset;
  unset.id = "id0000000009";
  const Json ju = unset.to_json();
  EXPECT_FALSE(ju["config"]["resources"].contains("memory_bytes"));
  Expected<ContainerState> back_unset = ContainerState::from_json(ju);
  ASSERT_TRUE(back_unset.has_value()) << back_unset.error().message();
  EXPECT_EQ(back_unset->config.resources.memory_bytes, std::nullopt);
}

TEST(ContainerStateJsonTest, UnsetContainerIpIsAbsentAndStaysUnset) {
  // container_ip absent means "auto-allocate"; a "" written in its place would
  // be a request for the empty address.
  ContainerState s;
  s.id = "id0000000010";
  EXPECT_FALSE(s.to_json()["config"]["network"].contains("container_ip"));

  Expected<ContainerState> back = ContainerState::from_json(s.to_json());
  ASSERT_TRUE(back.has_value()) << back.error().message();
  EXPECT_EQ(back->config.network.container_ip, std::nullopt);
}

TEST(ContainerStateJsonTest, WrongTypedOptionalReadsAsUnsetNotAsGarbage) {
  // A hand-edited file with "memory_bytes": "256M" must not become some
  // arbitrary number; unset is the only safe reading.
  ContainerState s;
  s.id = "id0000000011";
  Json j = s.to_json();
  j.object()["config"].object()["resources"].object()["memory_bytes"] =
      Json("256M");
  Expected<ContainerState> back = ContainerState::from_json(j);
  ASSERT_TRUE(back.has_value()) << back.error().message();
  EXPECT_EQ(back->config.resources.memory_bytes, std::nullopt);
}

// ---------------------------------------------------------------------------
// save / load / list / remove.
// ---------------------------------------------------------------------------
TEST_F(StateStoreTest, SaveThenLoadRoundTripsThroughTheFilesystem) {
  ContainerState in = FullyPopulated();
  ASSERT_TRUE(store_->save(in).has_value());

  Expected<ContainerState> out = store_->load(in.id);
  ASSERT_TRUE(out.has_value()) << out.error().message();
  EXPECT_EQ(out->to_json().dump(2), in.to_json().dump(2));
}

TEST_F(StateStoreTest, SavedFileIsPrettyPrintedAndNewlineTerminated) {
  // dump(2) plus a trailing newline is what makes `cat state.json` usable
  // while debugging a stuck container - the file is a diagnostic, not a blob.
  ContainerState s = Minimal("id0000000012");
  ASSERT_TRUE(store_->save(s).has_value());

  Expected<std::string> text = read_file(paths_.state_path(s.id));
  ASSERT_TRUE(text.has_value()) << text.error().message();
  EXPECT_EQ(text->front(), '{');
  EXPECT_EQ(text->back(), '\n');
  EXPECT_NE(text->find("\n  \"id\": "), std::string::npos) << *text;
}

TEST_F(StateStoreTest, SaveRefusesAnEmptyId) {
  // The id is the directory name; an empty one would write straight into the
  // state root and collide with every other container.
  ContainerState s;
  Expected<void> r = store_->save(s);
  ASSERT_FALSE(r.has_value());
  EXPECT_EQ(r.error().op(), Op::WriteState);
}

TEST_F(StateStoreTest, SaveIsIdempotentAndOverwrites) {
  ContainerState s = Minimal("id0000000013", "web");
  ASSERT_TRUE(store_->save(s).has_value());
  s.status = ContainerStatus::Stopped;
  s.exit_code = 3;
  ASSERT_TRUE(store_->save(s).has_value());

  Expected<ContainerState> out = store_->load(s.id);
  ASSERT_TRUE(out.has_value()) << out.error().message();
  EXPECT_EQ(out->status, ContainerStatus::Stopped);
  EXPECT_EQ(out->exit_code, 3);
}

TEST_F(StateStoreTest, LoadOfAnUnknownIdNamesTheFileItLookedFor) {
  Expected<ContainerState> r = store_->load("nosuchcontainer");
  ASSERT_FALSE(r.has_value());
  // The context is the whole point: an operator needs to know which path was
  // missing, not merely that "something" was.
  EXPECT_NE(r.error().message().find(paths_.state_path("nosuchcontainer")),
            std::string::npos)
      << r.error().message();
}

TEST_F(StateStoreTest, ListOnAFreshRootIsEmptyAndNotAnError) {
  // `ps` on a host that has never run a container prints an empty table.
  Expected<std::vector<ContainerState>> r = store_->list();
  ASSERT_TRUE(r.has_value()) << r.error().message();
  EXPECT_TRUE(r->empty());
}

TEST_F(StateStoreTest, ListOnAMissingRootIsEmptyAndNotAnError) {
  RemoveTree(root_);
  Expected<std::vector<ContainerState>> r = store_->list();
  ASSERT_TRUE(r.has_value()) << r.error().message();
  EXPECT_TRUE(r->empty());
  ASSERT_EQ(::mkdir(root_.c_str(), 0700), 0) << std::strerror(errno);
}

TEST_F(StateStoreTest, ListReturnsEverySavedContainer) {
  ASSERT_TRUE(store_->save(Minimal("aa11111111aa", "web")).has_value());
  ASSERT_TRUE(store_->save(Minimal("bb22222222bb", "db")).has_value());
  ASSERT_TRUE(store_->save(Minimal("cc33333333cc", "cache")).has_value());

  Expected<std::vector<ContainerState>> r = store_->list();
  ASSERT_TRUE(r.has_value()) << r.error().message();
  ASSERT_EQ(r->size(), 3u);

  std::vector<std::string> ids;
  for (const ContainerState& s : *r)
    ids.push_back(s.id);
  EXPECT_NE(std::find(ids.begin(), ids.end(), "aa11111111aa"), ids.end());
  EXPECT_NE(std::find(ids.begin(), ids.end(), "bb22222222bb"), ids.end());
  EXPECT_NE(std::find(ids.begin(), ids.end(), "cc33333333cc"), ids.end());
}

TEST_F(StateStoreTest, ListToleratesACorruptStateFileAmongValidOnes) {
  ASSERT_TRUE(store_->save(Minimal("aa11111111aa", "web")).has_value());
  ASSERT_TRUE(store_->save(Minimal("bb22222222bb", "db")).has_value());

  // Three ways a record goes bad in the field: hand-edited garbage, a write
  // truncated by a crash, and a directory with no state.json at all. None of
  // them may take `ps` down with them - the operator still needs to see, and
  // clean up, the containers that are fine.
  ASSERT_EQ(::mkdir(paths_.container_dir("dd44444444dd").c_str(), 0700), 0)
      << std::strerror(errno);
  ASSERT_TRUE(WriteRaw(paths_.state_path("dd44444444dd"), "not json at all\n"));

  ASSERT_EQ(::mkdir(paths_.container_dir("ee55555555ee").c_str(), 0700), 0)
      << std::strerror(errno);
  ASSERT_TRUE(WriteRaw(paths_.state_path("ee55555555ee"), "{\"id\": \"ee5"));

  ASSERT_EQ(::mkdir(paths_.container_dir("ff66666666ff").c_str(), 0700), 0)
      << std::strerror(errno);

  // A stray regular file directly in the state root is not a container dir.
  ASSERT_TRUE(WriteRaw(root_ + "/stray.txt", "ignore me"));

  Expected<std::vector<ContainerState>> r = store_->list();
  ASSERT_TRUE(r.has_value()) << r.error().message();
  ASSERT_EQ(r->size(), 2u);
  std::vector<std::string> ids;
  for (const ContainerState& s : *r)
    ids.push_back(s.id);
  EXPECT_NE(std::find(ids.begin(), ids.end(), "aa11111111aa"), ids.end());
  EXPECT_NE(std::find(ids.begin(), ids.end(), "bb22222222bb"), ids.end());

  // The corrupt one is still individually diagnosable; it is skipped by list,
  // not silently declared healthy.
  EXPECT_FALSE(store_->load("dd44444444dd").has_value());
}

TEST_F(StateStoreTest, RemoveDeletesTheWholeContainerDirectory) {
  ContainerState s = Minimal("aa11111111aa", "web");
  ASSERT_TRUE(store_->save(s).has_value());
  // Sibling files (logs, pid) must go too, or the directory would survive.
  ASSERT_EQ(::mkdir(paths_.log_dir(s.id).c_str(), 0700), 0)
      << std::strerror(errno);
  ASSERT_TRUE(WriteRaw(paths_.log_dir(s.id) + "/out.log", "hello\n"));
  ASSERT_TRUE(WriteRaw(paths_.pid_path(s.id), "1234\n"));

  ASSERT_TRUE(store_->remove(s.id).has_value());
  EXPECT_FALSE(path_exists(paths_.container_dir(s.id)));
  EXPECT_FALSE(store_->load(s.id).has_value());
  EXPECT_TRUE(store_->list()->empty());
}

TEST_F(StateStoreTest, RemoveOfAnUnknownOrEmptyIdIsAnError) {
  Expected<void> unknown = store_->remove("nosuchcontainer");
  ASSERT_FALSE(unknown.has_value());
  EXPECT_EQ(unknown.error().op(), Op::RemoveState);

  Expected<void> empty = store_->remove("");
  ASSERT_FALSE(empty.has_value());
  EXPECT_EQ(empty.error().op(), Op::RemoveState);
  // An empty id must never be taken to mean the state root itself.
  EXPECT_TRUE(path_exists(root_));
}

// ---------------------------------------------------------------------------
// resolve().
// ---------------------------------------------------------------------------
class ResolveTest : public StateStoreTest {
 protected:
  void SetUp() override {
    StateStoreTest::SetUp();
    ASSERT_TRUE(store_->save(Minimal("ab11111111aa", "web")).has_value());
    ASSERT_TRUE(store_->save(Minimal("ab22222222bb", "db")).has_value());
    ASSERT_TRUE(store_->save(Minimal("cd33333333cc", "cache")).has_value());
  }
};

TEST_F(ResolveTest, ByFullId) {
  Expected<ContainerState> r = store_->resolve("ab11111111aa");
  ASSERT_TRUE(r.has_value()) << r.error().message();
  EXPECT_EQ(r->name, "web");
}

TEST_F(ResolveTest, ByUniqueIdPrefix) {
  Expected<ContainerState> r = store_->resolve("cd");
  ASSERT_TRUE(r.has_value()) << r.error().message();
  EXPECT_EQ(r->id, "cd33333333cc");

  // A one-character prefix is fine as long as it is still unique.
  Expected<ContainerState> single = store_->resolve("c");
  ASSERT_TRUE(single.has_value()) << single.error().message();
  EXPECT_EQ(single->id, "cd33333333cc");
}

TEST_F(ResolveTest, ByName) {
  Expected<ContainerState> r = store_->resolve("db");
  ASSERT_TRUE(r.has_value()) << r.error().message();
  EXPECT_EQ(r->id, "ab22222222bb");
}

TEST_F(ResolveTest, AmbiguousPrefixErrorsAndNamesTheCandidates) {
  // Picking one arbitrarily would eventually stop the wrong container. The
  // operator can only disambiguate if the message tells them what matched.
  Expected<ContainerState> r = store_->resolve("ab");
  ASSERT_FALSE(r.has_value());
  const std::string msg = r.error().message();
  EXPECT_NE(msg.find("ambiguous"), std::string::npos) << msg;
  EXPECT_NE(msg.find("ab11111111aa"), std::string::npos) << msg;
  EXPECT_NE(msg.find("ab22222222bb"), std::string::npos) << msg;
  // The names are included too, because that is how a human recognises them.
  EXPECT_NE(msg.find("web"), std::string::npos) << msg;
  EXPECT_NE(msg.find("db"), std::string::npos) << msg;
  EXPECT_EQ(r.error().op(), Op::ReadState);
}

TEST_F(ResolveTest, NoMatchErrorsAndSaysWhereItLooked) {
  Expected<ContainerState> r = store_->resolve("zzz");
  ASSERT_FALSE(r.has_value());
  const std::string msg = r.error().message();
  EXPECT_NE(msg.find("no such container"), std::string::npos) << msg;
  EXPECT_NE(msg.find("zzz"), std::string::npos) << msg;
  EXPECT_NE(msg.find(root_), std::string::npos) << msg;
}

TEST_F(ResolveTest, EmptyTargetIsAnError) {
  Expected<ContainerState> r = store_->resolve("");
  ASSERT_FALSE(r.has_value());
  EXPECT_EQ(r.error().op(), Op::ReadState);
}

TEST_F(ResolveTest, DuplicateNamesErrorAndNameTheCandidates) {
  ASSERT_TRUE(store_->save(Minimal("ef77777777ee", "cache")).has_value());
  Expected<ContainerState> r = store_->resolve("cache");
  ASSERT_FALSE(r.has_value());
  const std::string msg = r.error().message();
  EXPECT_NE(msg.find("cd33333333cc"), std::string::npos) << msg;
  EXPECT_NE(msg.find("ef77777777ee"), std::string::npos) << msg;
}

// ---------------------------------------------------------------------------
// read_pid_start_time and the pid-reuse guard.
// ---------------------------------------------------------------------------
TEST(PidStartTimeTest, OurOwnPidHasAStableNonZeroValue) {
  // Field 22 is a fixed property of this incarnation of the pid. If it were
  // not stable across reads, comparing it later would be meaningless and the
  // reuse guard would reject live containers at random.
  std::optional<std::uint64_t> first = read_pid_start_time(::getpid());
  ASSERT_TRUE(first.has_value());
  EXPECT_NE(*first, 0u);
  std::optional<std::uint64_t> second = read_pid_start_time(::getpid());
  ASSERT_TRUE(second.has_value());
  EXPECT_EQ(*second, *first);
}

TEST(PidStartTimeTest, PidOneIsReadableAndDiffersFromOurs) {
  // Two different incarnations must not report the same start time, or the
  // comparison in is_alive() could not tell them apart.
  std::optional<std::uint64_t> init = read_pid_start_time(1);
  if (!init.has_value())
    GTEST_SKIP() << "/proc/1/stat is not readable in this environment";
  std::optional<std::uint64_t> ours = read_pid_start_time(::getpid());
  ASSERT_TRUE(ours.has_value());
  EXPECT_NE(*init, *ours);
}

TEST(PidStartTimeTest, ImpossiblePidsReturnNullopt) {
  // Well beyond any plausible /proc/sys/kernel/pid_max, so there is no chance
  // of accidentally reading a real process.
  EXPECT_EQ(read_pid_start_time(2000000000), std::nullopt);
  EXPECT_EQ(read_pid_start_time(0), std::nullopt);
  EXPECT_EQ(read_pid_start_time(-1), std::nullopt);
}

TEST_F(StateStoreTest, IsAliveAcceptsAMatchingStartTime) {
  ContainerState s = Minimal("aa11111111aa", "web");
  s.pid = ::getpid();
  std::optional<std::uint64_t> start = read_pid_start_time(::getpid());
  ASSERT_TRUE(start.has_value());
  s.pid_start_time = *start;
  EXPECT_TRUE(store_->is_alive(s));
}

TEST_F(StateStoreTest, IsAliveRejectsAMismatchedStartTime) {
  // THE pid-reuse guard. /proc/<pid> existing only proves that SOME process
  // holds that pid; the kernel recycles them. Without this check a stale
  // record would let stop/kill signal - and `ps` report as Running - a
  // completely unrelated process that merely inherited the number.
  ContainerState s = Minimal("aa11111111aa", "web");
  s.pid = ::getpid();  // definitely alive
  std::optional<std::uint64_t> start = read_pid_start_time(::getpid());
  ASSERT_TRUE(start.has_value());

  s.pid_start_time = *start + 1;
  EXPECT_FALSE(store_->is_alive(s));

  s.pid_start_time = *start - 1;
  EXPECT_FALSE(store_->is_alive(s));

  // A record that never captured a start time (0) is untrusted rather than
  // believed, for exactly the same reason.
  s.pid_start_time = 0;
  EXPECT_FALSE(store_->is_alive(s));

  // ...and the matching value still works, proving the pid itself was fine
  // and only the start time decided the outcome.
  s.pid_start_time = *start;
  EXPECT_TRUE(store_->is_alive(s));
}

TEST_F(StateStoreTest, IsAliveIsFalseForUnsetAndImpossiblePids) {
  ContainerState s = Minimal("aa11111111aa", "web");
  EXPECT_FALSE(store_->is_alive(s));  // pid defaults to -1

  s.pid = 0;
  EXPECT_FALSE(store_->is_alive(s));

  s.pid = 2000000000;
  s.pid_start_time = 12345u;
  EXPECT_FALSE(store_->is_alive(s));
}

TEST_F(StateStoreTest, RefreshDemotesARunningRecordWhoseProcessIsGone) {
  // The consequence of the guard: `ps` must never show Running for a record
  // whose pid was recycled or whose process exited unobserved.
  ContainerState s = Minimal("aa11111111aa", "web");
  s.status = ContainerStatus::Running;
  s.pid = ::getpid();
  std::optional<std::uint64_t> start = read_pid_start_time(::getpid());
  ASSERT_TRUE(start.has_value());
  s.pid_start_time = *start + 1;  // same pid, different incarnation

  Expected<ContainerState> refreshed = store_->refresh(s);
  ASSERT_TRUE(refreshed.has_value()) << refreshed.error().message();
  EXPECT_EQ(refreshed->status, ContainerStatus::Stopped);
  // We never observed the exit, so the only honest record is when we noticed.
  EXPECT_FALSE(refreshed->finished_at.empty());

  // A genuinely live record is left alone.
  s.pid_start_time = *start;
  Expected<ContainerState> live = store_->refresh(s);
  ASSERT_TRUE(live.has_value()) << live.error().message();
  EXPECT_EQ(live->status, ContainerStatus::Running);
}

TEST_F(StateStoreTest, RefreshDoesNotWriteToDisk) {
  // `ps` is read-only. Persisting the reconciliation here would make listing
  // containers mutate the store, which is the caller's decision to make.
  ContainerState s = Minimal("aa11111111aa", "web");
  s.status = ContainerStatus::Running;
  ASSERT_TRUE(store_->save(s).has_value());

  ASSERT_TRUE(store_->refresh(s).has_value());
  Expected<ContainerState> on_disk = store_->load(s.id);
  ASSERT_TRUE(on_disk.has_value()) << on_disk.error().message();
  EXPECT_EQ(on_disk->status, ContainerStatus::Running);
}

// ---------------------------------------------------------------------------
// Regression: a negative limit in a state file must read back as ABSENT, not
// as an engaged optional holding zero.
//
// read_optional_uint used to return as_uint()'s fallback of 0 wrapped in an
// engaged optional, which turned "no memory limit" into "a limit of zero
// bytes" - a limit the kernel enforces by killing the container the instant it
// allocates. This is the exact failure state_store.cpp's own header warns
// about, so it gets a test that would catch its return.
// ---------------------------------------------------------------------------
TEST_F(StateStoreTest, NegativeLimitReadsBackAsAbsentNotAsZero) {
  const char* kJson = R"({
    "id": "aabbccddeeff",
    "name": "neg",
    "status": "created",
    "pid": -1,
    "created_at": "2026-08-30T00:00:00.000Z",
    "config": {
      "id": "aabbccddeeff",
      "name": "neg",
      "rootfs_path": "/tmp/rootfs",
      "args": ["/bin/sh"],
      "resources": { "memory_bytes": -1, "pids_max": -5 }
    }
  })";

  Expected<Json> parsed = json_parse(kJson);
  ASSERT_TRUE(parsed) << parsed.error().message();
  Expected<ContainerState> state = ContainerState::from_json(*parsed);
  ASSERT_TRUE(state) << state.error().message();

  EXPECT_FALSE(state->config.resources.memory_bytes.has_value())
      << "a negative memory limit must be absent, not a zero limit: an "
         "engaged optional holding 0 means memory.max=0, which kills the "
         "container immediately";
  EXPECT_FALSE(state->config.resources.pids_max.has_value())
      << "same for pids.max: 0 would forbid the container from forking at all";
}

// A zero that was genuinely written stays a zero - the fix must not confuse
// "absent" with "explicitly zero", or it would trade one bug for another.
TEST_F(StateStoreTest, AnExplicitZeroLimitIsStillPreserved) {
  ContainerState in;
  in.id = "aabbccddeeff";
  in.name = "zero";
  in.created_at = "2026-08-30T00:00:00.000Z";
  in.config.id = in.id;
  in.config.name = in.name;
  in.config.rootfs_path = "/tmp/rootfs";
  in.config.args = {"/bin/sh"};
  in.config.resources.memory_bytes = 0;

  Expected<ContainerState> out = ContainerState::from_json(in.to_json());
  ASSERT_TRUE(out) << out.error().message();
  ASSERT_TRUE(out->config.resources.memory_bytes.has_value());
  EXPECT_EQ(*out->config.resources.memory_bytes, 0U);
}

}  // namespace
}  // namespace mc
