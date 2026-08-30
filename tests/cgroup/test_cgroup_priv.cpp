// SPDX-License-Identifier: MIT
//
// MiniContainer - cgroup v2 PRIVILEGED integration tests.
//
// These talk to the real kernel: they mkdir under /sys/fs/cgroup, write to
// cgroup.subtree_control, apply a limit, read the value back out of the
// filesystem, and put a real process inside a cgroup to prove rmdir refuses
// to remove it. Labelled "root" by tests/CMakeLists.txt, so `ctest -LE root`
// skips the whole binary.
//
// HOST SAFETY
// -----------
// Every test in this file works inside a scope directory named
// "minicontainer-test-<pid>", NEVER the real "minicontainer" scope. A test run
// therefore cannot disturb containers a developer actually has running, and
// two concurrent runs cannot collide. TearDown removes that scope
// unconditionally - after a passing test, a failing test, or a fatal
// assertion - killing anything left inside it first, because a leaked cgroup
// directory is host state this suite has no right to leave behind.
//
// SKIP, DON'T FAIL
// ----------------
// docs/cgroups.md records the measured fact that drives this: Ubuntu-24.04's
// WSL distro (systemd running) delegates "cpu memory pids" at the root, while
// docker-desktop's WSL distro has an EMPTY cgroup.subtree_control because
// nothing there runs systemd to do the delegation. A host that cannot
// delegate the memory controller is not a broken runtime - it is a host this
// particular assertion cannot be made on - so those tests GTEST_SKIP with the
// probed controller list in the message rather than failing.

#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <dirent.h>
#include <signal.h>
#include <unistd.h>

#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include "minicontainer/cgroup.h"
#include "minicontainer/config.h"
#include "minicontainer/errors.h"
#include "minicontainer/syscall.h"

#include <gtest/gtest.h>

// A macro, not a helper function: GTEST_SKIP() expands to a `return`, which
// must return out of the TEST body itself, not out of some function it was
// called from.
#define MC_REQUIRE_ROOT()              \
  do {                                 \
    if (::geteuid() != 0) {            \
      GTEST_SKIP() << "requires root"; \
    }                                  \
  } while (0)

namespace mc {
namespace {

// Polls until `pred` holds or the budget runs out. Process death and cgroup
// emptiness are both asynchronous: the kernel removes a task from
// cgroup.procs when it is reaped, not when kill() returns, so asserting
// instantaneously would make these tests flaky for reasons unrelated to the
// code under test.
template <class Pred>
bool wait_until(Pred pred, int budget_ms = 2000) {
  for (int waited = 0; waited < budget_ms; waited += 10) {
    if (pred())
      return true;
    ::usleep(10 * 1000);
  }
  return pred();
}

class CgroupPriv : public ::testing::Test {
 protected:
  void SetUp() override {
    // Unique per test-run process. NEVER the production "minicontainer"
    // scope: these tests delegate controllers and rmdir directories, and
    // doing either to the real scope would disturb live containers.
    paths_.cgroup_root = "/sys/fs/cgroup";
    paths_.cgroup_scope = "minicontainer-test-" + std::to_string(::getpid());
  }

  void TearDown() override {
    // Runs even when a test failed or aborted on a fatal assertion, which is
    // exactly when cleanup matters most.
    reap_stray_child();
    destroy_scope();
  }

  [[nodiscard]] std::string scope_path() const {
    return paths_.cgroup_root + "/" + paths_.cgroup_scope;
  }

  [[nodiscard]] std::string leaf_path(const std::string& id) const {
    return scope_path() + "/" + id;
  }

  // Forks a child that simply blocks. Used to put a real, living process
  // inside a cgroup. The pid is remembered so TearDown can always reap it.
  ::pid_t fork_blocking_child() {
    ::pid_t pid = ::fork();
    if (pid == 0) {
      // Child: no gtest calls here, and _exit so no atexit handler from the
      // test binary runs twice.
      ::pause();
      _exit(0);
    }
    stray_child_ = pid;
    return pid;
  }

  void reap_stray_child() {
    if (stray_child_ <= 0)
      return;
    ::kill(stray_child_, SIGKILL);
    int status = 0;
    ::waitpid(stray_child_, &status, 0);
    stray_child_ = -1;
  }

  // Removes every leaf under our scope and then the scope itself. Strictly
  // scoped: it only ever opens and rmdir's paths under scope_path(), so a bug
  // here cannot reach the host hierarchy.
  void destroy_scope() {
    const std::string scope = scope_path();
    if (!is_directory(scope))
      return;

    if (DIR* d = ::opendir(scope.c_str()); d != nullptr) {
      std::vector<std::string> leaves;
      while (const struct ::dirent* e = ::readdir(d)) {
        const std::string name = e->d_name;
        if (name == "." || name == "..")
          continue;
        const std::string child = scope + "/" + name;
        if (is_directory(child))
          leaves.push_back(child);
      }
      ::closedir(d);

      for (const std::string& leaf : leaves) {
        // cgroup.kill (5.14+) is the only way to be sure nothing forked out
        // from under us between listing and killing.
        const std::string kill_file = leaf + "/cgroup.kill";
        if (path_exists(kill_file))
          (void)write_file(kill_file, "1", Op::SignalChild);
        wait_until([&leaf] { return ::rmdir(leaf.c_str()) == 0; }, 2000);
      }
    }

    wait_until([&scope] { return ::rmdir(scope.c_str()) == 0; }, 2000);
  }

  RuntimePaths paths_;
  ::pid_t stray_child_ = -1;
};

// ---------------------------------------------------------------------------
// detect_cgroup_support - the probe that everything else depends on.
// ---------------------------------------------------------------------------

TEST_F(CgroupPriv, DetectReportsAUnifiedMountAndANonEmptyControllerList) {
  MC_REQUIRE_ROOT();

  Expected<CgroupSupport> support = detect_cgroup_support(paths_);
  // A failed probe is a real error; a successful probe with a negative answer
  // is not. Those are deliberately different outcomes, so assert the call
  // itself succeeded before looking at what it found.
  ASSERT_TRUE(support.has_value()) << support.error().message();

  if (!support->unified_mount) {
    GTEST_SKIP() << paths_.cgroup_root
                 << " is not a cgroup2 (unified) filesystem on this host; "
                    "MiniContainer does not implement cgroup v1";
  }

  EXPECT_FALSE(support->available.empty())
      << "a cgroup2 root always publishes cgroup.controllers; an empty list "
         "here means the probe read the wrong file or trimmed away the "
         "content";

  // The probe must not have invented a scope directory. It is documented as
  // read-only, and a probe with side effects would make `stats` on a
  // non-existent container create cgroups.
  EXPECT_FALSE(is_directory(scope_path()))
      << "detect_cgroup_support() must never write anything, but "
      << scope_path() << " now exists";

  // The flags must agree with the verbatim string they were derived from -
  // this is what catches a controller name typo'd in one place only.
  const bool memory_in_list =
      support->available.find("memory") != std::string::npos;
  if (support->memory) {
    EXPECT_TRUE(memory_in_list)
        << "support.memory is set but cgroup.controllers ('"
        << support->available << "') does not mention memory";
  }
}

// ---------------------------------------------------------------------------
// The full lifecycle: create -> apply a memory limit -> read the byte count
// back out of the filesystem -> remove.
// ---------------------------------------------------------------------------

TEST_F(CgroupPriv, CreateApplyMemoryLimitReadBackAndRemove) {
  MC_REQUIRE_ROOT();

  Expected<CgroupSupport> support = detect_cgroup_support(paths_);
  ASSERT_TRUE(support.has_value()) << support.error().message();
  if (!support->unified_mount)
    GTEST_SKIP() << paths_.cgroup_root << " is not a cgroup2 filesystem";
  if (!support->memory) {
    // docker-desktop's WSL distro lands here: cgroup v2 is mounted but
    // nothing is delegated, so no memory limit can be applied at all. That is
    // a property of the host, not a defect in the runtime.
    GTEST_SKIP() << "the memory controller is not delegated on this host "
                    "(cgroup.controllers='"
                 << support->available << "'); nothing can set memory.max here";
  }

  // 64 MiB, chosen so the exact decimal is unmistakable if the value is
  // rounded, scaled, or run through a size formatter on the way down.
  constexpr std::uint64_t kMemoryBytes = 67108864;
  Resources resources;
  resources.memory_bytes = kMemoryBytes;

  Expected<CgroupManager> mgr =
      CgroupManager::create(paths_, "alpha", resources);
  ASSERT_TRUE(mgr.has_value()) << mgr.error().message();

  // The leaf must be <root>/<scope>/<id> and nowhere else - the containment
  // property the whole teardown story rests on.
  EXPECT_EQ(mgr->path(), leaf_path("alpha"));
  EXPECT_TRUE(is_directory(mgr->path()));

  // The scope must be an internal node with memory delegated downward;
  // without that write the leaf would have no memory.max to write at all.
  Expected<std::string> subtree =
      read_file(scope_path() + "/cgroup.subtree_control", Op::DetectCgroup);
  ASSERT_TRUE(subtree.has_value()) << subtree.error().message();
  EXPECT_NE(subtree->find("memory"), std::string::npos)
      << "create() must delegate '+memory' to " << scope_path()
      << "; it currently has '" << *subtree << "'";

  ASSERT_TRUE(mgr->apply_limits(resources).has_value());

  // Read the file back from the filesystem, not from our own struct: the
  // point of this test is that the bytes reached the kernel and the kernel
  // accepted them unchanged.
  Expected<std::string> raw =
      read_file(mgr->path() + "/memory.max", Op::ReadCgroupStat);
  ASSERT_TRUE(raw.has_value()) << raw.error().message();
  EXPECT_EQ(std::strtoull(raw->c_str(), nullptr, 10), kMemoryBytes)
      << "memory.max reads back as '" << *raw << "'; the kernel rounds this "
      << "value to a page multiple, so 67108864 (a whole number of 4 KiB "
         "pages) must survive exactly";

  // read_stats() must agree with the raw file. A mismatch would mean the
  // "max" literal handling or the parser disagrees with what was written.
  Expected<CgroupStats> stats = mgr->read_stats();
  ASSERT_TRUE(stats.has_value()) << stats.error().message();
  ASSERT_TRUE(stats->memory_max.has_value())
      << "memory.max holds a number, so it must not decode as the unlimited "
         "'max' literal";
  EXPECT_EQ(*stats->memory_max, kMemoryBytes);

  // An empty cgroup can be removed immediately - no processes, no EBUSY.
  Expected<void> removed = mgr->remove();
  ASSERT_TRUE(removed.has_value()) << removed.error().message();
  EXPECT_FALSE(is_directory(leaf_path("alpha")));

  // remove() is idempotent by design: it is what Rollback calls, and failing
  // because the thing it wanted gone is already gone would mask the original
  // error that triggered the unwind.
  EXPECT_TRUE(mgr->remove().has_value());
}

// ---------------------------------------------------------------------------
// open() finds a cgroup create() made, and refuses one that does not exist.
// ---------------------------------------------------------------------------

TEST_F(CgroupPriv, OpenFindsAnExistingLeafAndRejectsAMissingOne) {
  MC_REQUIRE_ROOT();

  Expected<CgroupSupport> support = detect_cgroup_support(paths_);
  ASSERT_TRUE(support.has_value()) << support.error().message();
  if (!support->unified_mount)
    GTEST_SKIP() << paths_.cgroup_root << " is not a cgroup2 filesystem";

  // No Resources at all, so this needs no controller delegated whatsoever and
  // runs even on a host with an empty subtree_control.
  Expected<CgroupManager> created =
      CgroupManager::create(paths_, "beta", Resources{});
  ASSERT_TRUE(created.has_value()) << created.error().message();

  Expected<CgroupManager> reopened = CgroupManager::open(paths_, "beta");
  ASSERT_TRUE(reopened.has_value()) << reopened.error().message();
  EXPECT_EQ(reopened->path(), created->path());

  // `stats` and `stop` reach a container through open(); a missing cgroup has
  // to be a clean ENOENT rather than a manager bound to a path that is not
  // there, which would only fail later and less clearly.
  Expected<CgroupManager> missing = CgroupManager::open(paths_, "no-such-id");
  ASSERT_FALSE(missing.has_value());
  EXPECT_EQ(missing.error().err(), ENOENT);

  EXPECT_TRUE(created->remove().has_value());
}

// ---------------------------------------------------------------------------
// open_dir_fd() - the fd clone3() consumes for CLONE_INTO_CGROUP.
// ---------------------------------------------------------------------------

TEST_F(CgroupPriv, OpenDirFdYieldsADirectoryFdForCloneIntoCgroup) {
  MC_REQUIRE_ROOT();

  Expected<CgroupSupport> support = detect_cgroup_support(paths_);
  ASSERT_TRUE(support.has_value()) << support.error().message();
  if (!support->unified_mount)
    GTEST_SKIP() << paths_.cgroup_root << " is not a cgroup2 filesystem";

  Expected<CgroupManager> mgr =
      CgroupManager::create(paths_, "gamma", Resources{});
  ASSERT_TRUE(mgr.has_value()) << mgr.error().message();

  Expected<Fd> fd = mgr->open_dir_fd();
  ASSERT_TRUE(fd.has_value()) << fd.error().message();
  ASSERT_TRUE(fd->valid());

  // clone3() rejects anything that is not a cgroup directory fd, so the
  // O_DIRECTORY in open_dir_fd() is load-bearing rather than decorative.
  struct ::stat st {};
  ASSERT_EQ(::fstat(fd->get(), &st), 0);
  EXPECT_TRUE(S_ISDIR(st.st_mode));

  fd->reset();
  EXPECT_TRUE(mgr->remove().has_value());
}

// ---------------------------------------------------------------------------
// The headline safety property: rmdir must REFUSE while a process is inside.
//
// A remove() that silently succeeded here would leave the container process
// running with its limits gone - the cgroup that was enforcing them removed
// out from under it - which is precisely the failure teardown ordering exists
// to prevent.
// ---------------------------------------------------------------------------

TEST_F(CgroupPriv, RemoveFailsClearlyWhileACgroupStillHoldsAProcess) {
  MC_REQUIRE_ROOT();

  Expected<CgroupSupport> support = detect_cgroup_support(paths_);
  ASSERT_TRUE(support.has_value()) << support.error().message();
  if (!support->unified_mount)
    GTEST_SKIP() << paths_.cgroup_root << " is not a cgroup2 filesystem";

  Expected<CgroupManager> mgr =
      CgroupManager::create(paths_, "delta", Resources{});
  ASSERT_TRUE(mgr.has_value()) << mgr.error().message();

  const ::pid_t child = fork_blocking_child();
  ASSERT_GT(child, 0) << "fork failed: " << std::strerror(errno);

  Expected<void> attached = mgr->attach(child);
  ASSERT_TRUE(attached.has_value()) << attached.error().message();

  // Confirm from the kernel's side, not just from attach()'s return value.
  Expected<std::string> procs =
      read_file(mgr->path() + "/cgroup.procs", Op::ReadCgroupStat);
  ASSERT_TRUE(procs.has_value()) << procs.error().message();
  EXPECT_NE(procs->find(std::to_string(child)), std::string::npos)
      << "pid " << child << " is not listed in cgroup.procs ('" << *procs
      << "'), so the rest of this test would prove nothing";

  Expected<void> removed = mgr->remove();
  ASSERT_FALSE(removed.has_value())
      << "rmdir succeeded on a cgroup still holding pid " << child
      << "; the kernel must refuse this, and a silent success would mean the "
         "container kept running with no cgroup enforcing its limits";
  EXPECT_EQ(removed.error().err(), EBUSY)
      << "the kernel signals a populated cgroup with EBUSY specifically";
  EXPECT_EQ(removed.error().op(), Op::RemoveCgroup);

  const std::string message = removed.error().message();
  // The message has to be a diagnosis, not "rmdir: Device or resource busy".
  // EBUSY here is never transient, so the text must point at the actual cause
  // rather than inviting a retry loop.
  EXPECT_NE(message.find("still contains processes"), std::string::npos)
      << message;
  EXPECT_NE(message.find(mgr->path()), std::string::npos) << message;

  // Now do it properly: kill everything in the cgroup, wait for the process
  // to actually be reaped, and only then remove. Signalling is not exiting -
  // that gap is the whole point of the EBUSY above.
  ASSERT_TRUE(mgr->kill_all(SIGKILL).has_value());

  int status = 0;
  ASSERT_EQ(::waitpid(child, &status, 0), child);
  stray_child_ = -1;  // reaped; TearDown must not wait on it again
  EXPECT_TRUE(WIFSIGNALED(status));

  const std::string leaf = mgr->path();
  EXPECT_TRUE(wait_until([&mgr] { return mgr->remove().has_value(); }))
      << "once every process has actually exited, rmdir must succeed";
  EXPECT_FALSE(is_directory(leaf));
}

// ---------------------------------------------------------------------------
// kill_all() reaches a process the cgroup holds, which is how `stop`
// guarantees it caught every descendant rather than only the entrypoint.
// ---------------------------------------------------------------------------

TEST_F(CgroupPriv, KillAllTerminatesAProcessInsideTheCgroup) {
  MC_REQUIRE_ROOT();

  Expected<CgroupSupport> support = detect_cgroup_support(paths_);
  ASSERT_TRUE(support.has_value()) << support.error().message();
  if (!support->unified_mount)
    GTEST_SKIP() << paths_.cgroup_root << " is not a cgroup2 filesystem";

  Expected<CgroupManager> mgr =
      CgroupManager::create(paths_, "epsilon", Resources{});
  ASSERT_TRUE(mgr.has_value()) << mgr.error().message();

  const ::pid_t child = fork_blocking_child();
  ASSERT_GT(child, 0);
  ASSERT_TRUE(mgr->attach(child).has_value());

  // SIGTERM, not SIGKILL: this deliberately exercises the cgroup.procs pid
  // loop rather than the cgroup.kill fast path, because cgroup.kill always
  // sends SIGKILL and using it for a graceful stop would silently upgrade
  // every stop into a hard kill.
  ASSERT_TRUE(mgr->kill_all(SIGTERM).has_value());

  int status = 0;
  ASSERT_EQ(::waitpid(child, &status, 0), child);
  stray_child_ = -1;
  EXPECT_TRUE(WIFSIGNALED(status));
  EXPECT_EQ(WTERMSIG(status), SIGTERM)
      << "kill_all(SIGTERM) must deliver SIGTERM, not upgrade it to SIGKILL "
         "via cgroup.kill";

  EXPECT_TRUE(wait_until([&mgr] { return mgr->remove().has_value(); }));
}

// ---------------------------------------------------------------------------
// A limit whose controller is not delegated must fail BEFORE anything is
// created, naming the controller. A half-built cgroup silently missing
// memory.max is the exact failure docs/cgroups.md warns about.
// ---------------------------------------------------------------------------

TEST_F(CgroupPriv, AnUndelegatedControllerFailsUpFrontAndNamesItself) {
  MC_REQUIRE_ROOT();

  Expected<CgroupSupport> support = detect_cgroup_support(paths_);
  ASSERT_TRUE(support.has_value()) << support.error().message();
  if (!support->unified_mount)
    GTEST_SKIP() << paths_.cgroup_root << " is not a cgroup2 filesystem";

  // Pick a controller this host genuinely does not offer us. On Ubuntu-24.04
  // + systemd that is cpuset (the root delegates only "cpu memory pids"); on
  // docker-desktop it is all of them.
  Resources resources;
  std::string controller;
  if (!support->cpuset) {
    resources.cpuset_cpus = "0";
    controller = "cpuset";
  } else if (!support->memory) {
    resources.memory_bytes = 4096;
    controller = "memory";
  } else if (!support->pids) {
    resources.pids_max = 16;
    controller = "pids";
  } else if (!support->cpu) {
    resources.cpus = 1.0;
    controller = "cpu";
  } else {
    GTEST_SKIP() << "this host delegates every controller MiniContainer can "
                    "limit (cgroup.controllers='"
                 << support->available
                 << "'), so there is no undelegated case to provoke";
  }

  Expected<CgroupManager> mgr =
      CgroupManager::create(paths_, "zeta", resources);
  ASSERT_FALSE(mgr.has_value())
      << "the '" << controller
      << "' controller is not usable here, so create() must refuse rather "
         "than build a cgroup whose limit can never be applied";
  EXPECT_EQ(mgr.error().op(), Op::EnableController);

  const std::string message = mgr.error().message();
  // Naming the controller is the whole value of this error: "ENOENT on
  // cpuset.cpus" three steps later explains nothing.
  EXPECT_NE(message.find(controller), std::string::npos) << message;
  EXPECT_NE(message.find("subtree_control"), std::string::npos) << message;

  // Fail-before-create: nothing may be left on the host after a refusal.
  EXPECT_FALSE(is_directory(leaf_path("zeta")))
      << "create() refused but still left " << leaf_path("zeta") << " behind";
}

}  // namespace
}  // namespace mc
