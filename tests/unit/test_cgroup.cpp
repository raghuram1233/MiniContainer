// SPDX-License-Identifier: MIT
//
// MiniContainer - cgroup v2 UNPRIVILEGED unit tests.
//
// This suite deliberately never touches /sys/fs/cgroup. Everything here is
// either a pure function (cgroup_limit_writes, CgroupSupport::supports) or an
// early-return guard that fires before any syscall (the id check in
// CgroupManager::create/open, the "not bound to a cgroup" check in every
// CgroupManager method). That is the point: the mapping from Resources to the
// exact bytes the kernel receives is the part of the module most likely to be
// silently wrong, and it is also the part that needs neither root nor a
// cgroup2 mount to verify. See tests/cgroup/test_cgroup_priv.cpp for the half
// that does talk to the kernel.
//
// The single most important behaviour asserted here is that an unset
// (std::nullopt) Resources field produces NO write at all. "No limit" and
// "a limit that happens to be zero" are different states, and conflating them
// would mean pids.max=0 (no forking ever) or memory.max=0 (OOM-killed on the
// first allocation) for every container that simply did not ask for a limit.

#include <signal.h>
#include <unistd.h>

#include <algorithm>
#include <string>
#include <vector>

#include "minicontainer/cgroup.h"
#include "minicontainer/config.h"
#include "minicontainer/errors.h"

#include <gtest/gtest.h>

namespace mc {
namespace {

// Finds the single write for `file`, or returns nullptr. Used so the
// per-field tests assert on content rather than on positional index, which
// would make them fail for the wrong reason if the emission order changed.
const CgroupLimitWrite* find(const std::vector<CgroupLimitWrite>& writes,
                             const std::string& file) {
  auto it = std::find_if(
      writes.begin(), writes.end(),
      [&file](const CgroupLimitWrite& w) { return w.file == file; });
  return it == writes.end() ? nullptr : &*it;
}

// ---------------------------------------------------------------------------
// cgroup_limit_writes - the pure heart of the module.
// ---------------------------------------------------------------------------

TEST(CgroupLimitWrites, NoResourcesSetProducesAnEmptyVector) {
  const Resources none;
  const std::vector<CgroupLimitWrite> writes = cgroup_limit_writes(none);

  // Not "a vector of defaults", not "a vector of max" - EMPTY. Every entry
  // this function emits becomes a real write() into cgroupfs, so an entry we
  // were never asked for is an unrequested change to how a container runs.
  EXPECT_TRUE(writes.empty())
      << "a default-constructed Resources asks for nothing, so nothing may be "
         "written; the first unexpected entry was '"
      << (writes.empty() ? std::string() : writes.front().file) << "'";
}

TEST(CgroupLimitWrites, MemoryBytesMapsToMemoryMax) {
  Resources r;
  r.memory_bytes = 268435456;  // 256 MiB

  const std::vector<CgroupLimitWrite> writes = cgroup_limit_writes(r);
  ASSERT_EQ(writes.size(), 1u) << "one field set means exactly one write";
  EXPECT_EQ(writes[0].file, "memory.max");
  // Plain decimal bytes: cgroup v2 does not accept "256M" the way our CLI
  // does, so parse_memory_size() must already have run by this point.
  EXPECT_EQ(writes[0].value, "268435456");
  EXPECT_EQ(writes[0].controller, "memory");
}

TEST(CgroupLimitWrites, MemorySwapBytesMapsToMemorySwapMax) {
  Resources r;
  r.memory_swap_bytes = 134217728;  // 128 MiB

  const std::vector<CgroupLimitWrite> writes = cgroup_limit_writes(r);
  ASSERT_EQ(writes.size(), 1u);
  // memory.swap.max, NOT cgroup v1's memory.memsw.limit_in_bytes: v2's swap
  // limit sits on top of memory.max rather than including it, and writing the
  // v1 name here would just be an ENOENT with no explanation.
  EXPECT_EQ(writes[0].file, "memory.swap.max");
  EXPECT_EQ(writes[0].value, "134217728");
  // Swap is accounted by the memory controller, so this is what the
  // delegation check must key off - there is no "swap" controller.
  EXPECT_EQ(writes[0].controller, "memory");
}

TEST(CgroupLimitWrites, HalfACpuRendersAsQuotaThenPeriod) {
  Resources r;
  r.cpus = 0.5;

  const std::vector<CgroupLimitWrite> writes = cgroup_limit_writes(r);
  ASSERT_EQ(writes.size(), 1u);
  EXPECT_EQ(writes[0].file, "cpu.max");
  // "<quota> <period>" in microseconds, quota FIRST. Reversed ("100000 50000")
  // is still two valid integers, so the kernel accepts it silently and the
  // container ends up with 2 CPUs instead of half of one. Only an exact string
  // comparison catches that.
  EXPECT_EQ(writes[0].value, "50000 100000");
  EXPECT_EQ(writes[0].controller, "cpu");
}

TEST(CgroupLimitWrites,
     WholeAndFractionalCpuCountsScaleAgainstTheDefaultPeriod) {
  const struct {
    double cpus;
    const char* expected;
  } kCases[] = {
      {1.0, "100000 100000"},
      {1.5, "150000 100000"},
      {2.0, "200000 100000"},
      {0.1, "10000 100000"},
  };

  for (const auto& c : kCases) {
    Resources r;
    r.cpus = c.cpus;
    const std::vector<CgroupLimitWrite> writes = cgroup_limit_writes(r);
    ASSERT_EQ(writes.size(), 1u) << "cpus=" << c.cpus;
    EXPECT_EQ(writes[0].value, c.expected)
        << "cpus=" << c.cpus << " must scale against the "
        << Resources::kDefaultCpuPeriodUs << "us default period";
  }
}

TEST(CgroupLimitWrites, NonPositiveCpusEmitsNothingRatherThanAZeroQuota) {
  // validate() rejects these before we ever get here, but cpu.max="0 100000"
  // would be a cgroup that may never run - far worse than the no-op that
  // cpu_max_value()'s nullopt produces. Defence in depth for a value that
  // must never reach the kernel.
  for (double bad : {0.0, -1.0}) {
    Resources r;
    r.cpus = bad;
    EXPECT_TRUE(cgroup_limit_writes(r).empty())
        << "cpus=" << bad << " must not produce a cpu.max write";
  }
}

TEST(CgroupLimitWrites, CpuSharesMapsToCpuWeight) {
  Resources r;
  r.cpu_shares = 512;

  const std::vector<CgroupLimitWrite> writes = cgroup_limit_writes(r);
  ASSERT_EQ(writes.size(), 1u);
  // cpu.weight is the relative share, a different file and a different
  // meaning from cpu.max's hard ceiling. A container may set either or both.
  EXPECT_EQ(writes[0].file, "cpu.weight");
  EXPECT_EQ(writes[0].value, "512");
  EXPECT_EQ(writes[0].controller, "cpu");
}

TEST(CgroupLimitWrites, PidsMaxMapsToPidsMax) {
  Resources r;
  r.pids_max = 64;

  const std::vector<CgroupLimitWrite> writes = cgroup_limit_writes(r);
  ASSERT_EQ(writes.size(), 1u);
  EXPECT_EQ(writes[0].file, "pids.max");
  EXPECT_EQ(writes[0].value, "64");
  EXPECT_EQ(writes[0].controller, "pids");
}

TEST(CgroupLimitWrites, CpusetCpusIsPassedThroughVerbatim) {
  Resources r;
  r.cpuset_cpus = "0-3,8";

  const std::vector<CgroupLimitWrite> writes = cgroup_limit_writes(r);
  ASSERT_EQ(writes.size(), 1u);
  EXPECT_EQ(writes[0].file, "cpuset.cpus");
  // The kernel owns this grammar (ranges, commas). Re-rendering it here could
  // only lose information, so the string must survive untouched.
  EXPECT_EQ(writes[0].value, "0-3,8");
  // cpuset is delegated independently of cpu; tagging it "cpu" would let a
  // host that delegates only cpu sail past the check and fail on ENOENT.
  EXPECT_EQ(writes[0].controller, "cpuset");
}

TEST(CgroupLimitWrites, AnExplicitZeroIsStillWritten) {
  Resources r;
  r.memory_bytes = 0;

  const std::vector<CgroupLimitWrite> writes = cgroup_limit_writes(r);
  // The mirror image of NoResourcesSetProducesAnEmptyVector: 0 is a value the
  // caller supplied, so it is written. Only std::nullopt means "leave alone".
  // These two tests together pin the has_value() check rather than a
  // truthiness check on the underlying integer.
  ASSERT_EQ(writes.size(), 1u);
  EXPECT_EQ(writes[0].file, "memory.max");
  EXPECT_EQ(writes[0].value, "0");
}

TEST(CgroupLimitWrites,
     EveryFieldSetProducesEveryWriteTaggedWithItsController) {
  Resources r;
  r.memory_bytes = 1048576;
  r.memory_swap_bytes = 2097152;
  r.cpus = 2.0;
  r.cpu_shares = 200;
  r.pids_max = 100;
  r.cpuset_cpus = "0-1";

  const std::vector<CgroupLimitWrite> writes = cgroup_limit_writes(r);
  ASSERT_EQ(writes.size(), 6u) << "six fields set means six writes; nothing "
                                  "may be merged or dropped";

  // Order matters for the memory pair: memory.max before memory.swap.max is
  // the order the kernel wants the two set in.
  EXPECT_EQ(writes[0].file, "memory.max");
  EXPECT_EQ(writes[1].file, "memory.swap.max");

  struct Expectation {
    const char* file;
    const char* value;
    const char* controller;
  };
  const Expectation kExpected[] = {
      {"memory.max", "1048576", "memory"},
      {"memory.swap.max", "2097152", "memory"},
      {"cpu.max", "200000 100000", "cpu"},
      {"cpu.weight", "200", "cpu"},
      {"pids.max", "100", "pids"},
      {"cpuset.cpus", "0-1", "cpuset"},
  };
  for (const Expectation& e : kExpected) {
    const CgroupLimitWrite* w = find(writes, e.file);
    ASSERT_NE(w, nullptr) << e.file << " is missing from the write set";
    EXPECT_EQ(w->value, e.value) << e.file;
    // The controller tag is what CgroupManager::create feeds to the
    // delegation probe. A wrong tag means either a spurious "controller not
    // usable" refusal or - worse - a missing check and a bare ENOENT later.
    EXPECT_EQ(w->controller, e.controller) << e.file;
  }
}

TEST(CgroupLimitWrites, OnlyTheControllersActuallyNeededAreMentioned) {
  Resources r;
  r.memory_bytes = 4096;
  r.pids_max = 8;

  const std::vector<CgroupLimitWrite> writes = cgroup_limit_writes(r);
  ASSERT_EQ(writes.size(), 2u);
  for (const CgroupLimitWrite& w : writes) {
    // No "cpu" and no "cpuset" anywhere: create() enables exactly the
    // controllers named here, and on a host with partial delegation asking
    // for cpuset would fail a container that only ever wanted memory + pids.
    EXPECT_NE(w.controller, "cpu");
    EXPECT_NE(w.controller, "cpuset");
    EXPECT_NE(w.controller, "io");
  }
  EXPECT_NE(find(writes, "memory.max"), nullptr);
  EXPECT_NE(find(writes, "pids.max"), nullptr);
}

// ---------------------------------------------------------------------------
// CgroupSupport::supports - pure lookup over the probed flags.
// ---------------------------------------------------------------------------

TEST(CgroupSupportProbe, DefaultConstructedSupportsNothing) {
  const CgroupSupport s;
  EXPECT_FALSE(s.unified_mount);
  // The safe default: before the probe has run we must assume nothing is
  // available, so a missed probe fails loudly instead of writing blind.
  EXPECT_FALSE(s.supports("cpu"));
  EXPECT_FALSE(s.supports("memory"));
  EXPECT_FALSE(s.supports("pids"));
  EXPECT_FALSE(s.supports("cpuset"));
  EXPECT_FALSE(s.supports("io"));
}

TEST(CgroupSupportProbe, ReportsPresentControllersAndOnlyThose) {
  CgroupSupport s;
  s.unified_mount = true;
  // Exactly the Ubuntu-24.04 + systemd WSL layout described in
  // docs/cgroups.md: the root delegates cpu/memory/pids but NOT cpuset or io.
  s.cpu = true;
  s.memory = true;
  s.pids = true;

  EXPECT_TRUE(s.supports("cpu"));
  EXPECT_TRUE(s.supports("memory"));
  EXPECT_TRUE(s.supports("pids"));
  EXPECT_FALSE(s.supports("cpuset"))
      << "cpuset is delegated separately from cpu; claiming it here is how a "
         "--cpuset-cpus container ends up with a bare ENOENT on cpuset.cpus";
  EXPECT_FALSE(s.supports("io"));
}

TEST(CgroupSupportProbe, UnknownControllerIsNeverSupported) {
  CgroupSupport s;
  s.unified_mount = true;
  s.cpu = s.memory = s.pids = s.cpuset = s.io = true;

  // Even with every known flag on, a name we do not model must answer false.
  // Answering true would let a typo ("memroy", "cpu_set") pass the delegation
  // check and surface much later as an unexplained ENOENT on the write.
  EXPECT_FALSE(s.supports("memroy"));
  EXPECT_FALSE(s.supports("hugetlb"));
  EXPECT_FALSE(s.supports("rdma"));
  EXPECT_FALSE(s.supports(""));
  EXPECT_FALSE(s.supports("Memory")) << "controller names are case-sensitive "
                                        "kernel tokens, not free text";
}

// ---------------------------------------------------------------------------
// CgroupManager guards that fire before any syscall.
//
// Every method below checks "am I bound to a cgroup?" first, so these run
// without root and without a cgroup2 mount - no path is ever opened.
// ---------------------------------------------------------------------------

TEST(CgroupManagerUnbound, DefaultConstructedHasNoPath) {
  const CgroupManager mgr;
  EXPECT_TRUE(mgr.path().empty());
}

TEST(CgroupManagerUnbound, EveryOperationFailsWithItsOwnOp) {
  CgroupManager mgr;
  Resources r;
  r.memory_bytes = 4096;

  // The Op carried by each failure is what the CLI turns into "Failed to
  // ...". Getting it right is why they are asserted individually rather than
  // just checking has_value().
  Expected<void> limits = mgr.apply_limits(r);
  ASSERT_FALSE(limits.has_value());
  EXPECT_EQ(limits.error().op(), Op::WriteCgroupLimit);

  Expected<Fd> dir_fd = mgr.open_dir_fd();
  ASSERT_FALSE(dir_fd.has_value());
  EXPECT_EQ(dir_fd.error().op(), Op::OpenFile);

  Expected<void> attached = mgr.attach(::getpid());
  ASSERT_FALSE(attached.has_value());
  EXPECT_EQ(attached.error().op(), Op::AttachCgroup);

  Expected<CgroupStats> stats = mgr.read_stats();
  ASSERT_FALSE(stats.has_value());
  EXPECT_EQ(stats.error().op(), Op::ReadCgroupStat);

  Expected<void> removed = mgr.remove();
  ASSERT_FALSE(removed.has_value());
  EXPECT_EQ(removed.error().op(), Op::RemoveCgroup);

  Expected<void> killed = mgr.kill_all(SIGKILL);
  ASSERT_FALSE(killed.has_value());
  EXPECT_EQ(killed.error().op(), Op::SignalChild);
}

TEST(CgroupManagerUnbound, ApplyLimitsRefusesEvenWithNothingToWrite) {
  CgroupManager mgr;
  // An unbound manager is a programming error regardless of whether the
  // Resources happen to be empty. Returning Ok() here would let a caller that
  // forgot to call create() believe its (empty) limits had been applied.
  EXPECT_FALSE(mgr.apply_limits(Resources{}).has_value());
}

// ---------------------------------------------------------------------------
// Container id validation. check_id() runs BEFORE detect_cgroup_support(), so
// these calls reject the id without ever reaching cgroupfs. The paths below
// point at a directory that does not exist anyway, so even a regression that
// moved the probe earlier could not touch the host's real hierarchy.
// ---------------------------------------------------------------------------

RuntimePaths unreachable_paths() {
  RuntimePaths paths;
  paths.cgroup_root = "/nonexistent/mc-unit-test/sys/fs/cgroup";
  paths.cgroup_scope = "minicontainer-unit-test";
  return paths;
}

TEST(CgroupIdValidation, EmptyIdIsRejected) {
  const RuntimePaths paths = unreachable_paths();
  Expected<CgroupManager> mgr = CgroupManager::create(paths, "", Resources{});
  ASSERT_FALSE(mgr.has_value());
  EXPECT_EQ(mgr.error().op(), Op::CreateCgroup);
  EXPECT_NE(mgr.error().message().find("empty container id"), std::string::npos)
      << mgr.error().message();
}

TEST(CgroupIdValidation, IdsThatCouldEscapeTheScopeAreRejected) {
  const RuntimePaths paths = unreachable_paths();
  // The whole safety argument for teardown is that rmdir only ever touches
  // <root>/<scope>/<id>. An id containing '/' or equal to ".." would let a
  // caller aim that rmdir at an arbitrary cgroup - including the host's own.
  for (const char* bad : {"a/b", "..", ".", "../../system.slice", "x/"}) {
    Expected<CgroupManager> mgr =
        CgroupManager::create(paths, bad, Resources{});
    ASSERT_FALSE(mgr.has_value()) << "id '" << bad << "' must be rejected";
    EXPECT_EQ(mgr.error().op(), Op::CreateCgroup) << bad;
  }
}

TEST(CgroupIdValidation, OpenAppliesTheSameIdRules) {
  const RuntimePaths paths = unreachable_paths();
  // open() is the teardown/stats entry point and takes ids straight from the
  // state store, so it needs exactly the same guard create() has.
  Expected<CgroupManager> mgr = CgroupManager::open(paths, "../escape");
  ASSERT_FALSE(mgr.has_value());
  EXPECT_EQ(mgr.error().op(), Op::CreateCgroup);
}

}  // namespace
}  // namespace mc
