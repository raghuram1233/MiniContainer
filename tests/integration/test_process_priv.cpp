// SPDX-License-Identifier: MIT
//
// MiniContainer - process layer PRIVILEGED integration tests. These create
// real namespaces, real clone3() processes, and manipulate this test
// binary's own signal mask / subreaper flag - all things that need root and
// a real Linux kernel. Every test SKIPs rather than fails when it cannot get
// what it needs (root, a kernel feature), per the run instructions for this
// suite.

#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <sched.h>
#include <signal.h>
#include <unistd.h>

#include <cstdlib>
#include <cstring>
#include <optional>
#include <string>

#include "minicontainer/errors.h"
#include "minicontainer/process.h"
#include "minicontainer/syscall.h"

#include <gtest/gtest.h>

// A macro, not a helper function: GTEST_SKIP() expands to a `return`, which
// must return out of the TEST body itself, not out of some function it was
// called from.
#define MC_REQUIRE_ROOT()                                           \
  do {                                                              \
    if (::geteuid() != 0) {                                         \
      GTEST_SKIP() << "requires root (euid=" << ::geteuid() << ")"; \
    }                                                               \
  } while (0)

namespace mc {
namespace {

// ---------------------------------------------------------------------------
// clone_process with CLONE_NEWPID|CLONE_NEWUTS: the child sees getpid()==1.
// ---------------------------------------------------------------------------

int report_getpid_child(void* arg) {
  int fd = *static_cast<int*>(arg);
  ::pid_t p = ::getpid();
  // Raw write(), not Pipe::write_byte(): this runs as the clone3 child_fn and
  // must not allocate, but a raw write() of a POD is fine either way.
  (void)::write(fd, &p, sizeof(p));
  return 0;
}

TEST(ClonePidUts, ChildIsPidOneInNewNamespace) {
  MC_REQUIRE_ROOT();

  Expected<Pipe> pipe_r = Pipe::create();
  ASSERT_TRUE(pipe_r.has_value()) << pipe_r.error().message();
  Pipe p = std::move(pipe_r).value();
  int wfd = p.write_end.get();

  CloneRequest req;
  req.flags = CLONE_NEWPID | CLONE_NEWUTS;
  req.exit_signal = SIGCHLD;

  Expected<CloneResult> r = clone_process(req, &report_getpid_child, &wfd);
  ASSERT_TRUE(r.has_value()) << r.error().message();
  EXPECT_GT(r->pid, 0);

  p.write_end.reset();
  ::pid_t child_view_of_self = -1;
  ssize_t n =
      ::read(p.read_end.get(), &child_view_of_self, sizeof(child_view_of_self));
  ASSERT_EQ(n, static_cast<ssize_t>(sizeof(child_view_of_self)));

  EXPECT_EQ(child_view_of_self, 1)
      << "a process born directly into a new PID namespace via clone3 must "
         "see itself as PID 1 inside that namespace";
  EXPECT_NE(r->pid, child_view_of_self)
      << "the parent's view of the child's pid (host namespace) must differ "
         "from the child's own view (container namespace)";

  Expected<ExitStatus> status = wait_for(r->pid);
  ASSERT_TRUE(status.has_value()) << status.error().message();
  EXPECT_TRUE(status->exited);
}

// ---------------------------------------------------------------------------
// CLONE_NEWUTS: child's sethostname() must not leak to the parent.
// ---------------------------------------------------------------------------

int sethostname_child(void*) {
  static const char kName[] = "mc-test";
  ::sethostname(kName, sizeof(kName) - 1);
  return 0;
}

TEST(CloneNewUts, ChildHostnameChangeIsIsolated) {
  MC_REQUIRE_ROOT();

  char before[256] = {};
  ASSERT_EQ(::gethostname(before, sizeof(before)), 0);

  CloneRequest req;
  req.flags = CLONE_NEWUTS;
  req.exit_signal = SIGCHLD;

  Expected<CloneResult> r = clone_process(req, &sethostname_child, nullptr);
  ASSERT_TRUE(r.has_value()) << r.error().message();

  Expected<ExitStatus> status = wait_for(r->pid);
  ASSERT_TRUE(status.has_value()) << status.error().message();
  EXPECT_TRUE(status->exited);

  char after[256] = {};
  ASSERT_EQ(::gethostname(after, sizeof(after)), 0);

  EXPECT_STREQ(before, after)
      << "the child changed hostname inside its own UTS namespace; the "
         "parent's (host) hostname must be completely unaffected - this is "
         "the test that proves isolation, not merely that clone3 returned 0";
}

// ---------------------------------------------------------------------------
// CLONE_PIDFD yields a valid pidfd, and signal_process() via that pidfd
// works.
// ---------------------------------------------------------------------------

int pause_child(void*) {
  ::pause();  // blocks until any signal arrives
  return 0;
}

TEST(ClonePidfd, PidfdIsValidAndSignalProcessWorksThroughIt) {
  MC_REQUIRE_ROOT();

  CloneRequest req;
  req.flags = CLONE_PIDFD;
  req.exit_signal = SIGCHLD;

  Expected<CloneResult> r = clone_process(req, &pause_child, nullptr);
  ASSERT_TRUE(r.has_value()) << r.error().message();
  ASSERT_TRUE(r->pidfd.valid())
      << "CLONE_PIDFD was requested; pidfd must be valid";

  Expected<void> sig = signal_process(r->pidfd, r->pid, SIGKILL);
  ASSERT_TRUE(sig.has_value()) << sig.error().message();

  Expected<ExitStatus> status = wait_for(r->pid);
  ASSERT_TRUE(status.has_value()) << status.error().message();
  EXPECT_TRUE(status->signaled);
  EXPECT_EQ(status->signal, SIGKILL);
}

// ---------------------------------------------------------------------------
// CLONE_NEWUSER without writing uid_map: the child is left with an unmapped,
// overflow uid. This is exactly why the parent-writes-uid_map handshake in
// process.h exists - without it, privileged operations the child tries next
// would fail as "nobody" (65534), not as its intended uid.
// ---------------------------------------------------------------------------

int report_getuid_child(void* arg) {
  int fd = *static_cast<int*>(arg);
  ::uid_t u = ::getuid();
  (void)::write(fd, &u, sizeof(u));
  return 0;
}

::uid_t read_overflow_uid() {
  Expected<std::string> content = read_file("/proc/sys/kernel/overflowuid");
  if (!content.has_value())
    return 65534;  // documented kernel default
  return static_cast<::uid_t>(std::strtoul(content->c_str(), nullptr, 10));
}

TEST(CloneNewUser, UnmappedChildUidIsOverflowUid) {
  MC_REQUIRE_ROOT();

  Expected<Pipe> pipe_r = Pipe::create();
  ASSERT_TRUE(pipe_r.has_value()) << pipe_r.error().message();
  Pipe p = std::move(pipe_r).value();
  int wfd = p.write_end.get();

  CloneRequest req;
  req.flags = CLONE_NEWUSER;
  req.exit_signal = SIGCHLD;

  Expected<CloneResult> r = clone_process(req, &report_getuid_child, &wfd);
  ASSERT_TRUE(r.has_value()) << r.error().message();

  p.write_end.reset();
  ::uid_t seen_uid = 0;
  ssize_t n = ::read(p.read_end.get(), &seen_uid, sizeof(seen_uid));
  ASSERT_EQ(n, static_cast<ssize_t>(sizeof(seen_uid)));

  EXPECT_EQ(seen_uid, read_overflow_uid())
      << "no uid_map was ever written for the child's new user namespace, "
         "so the kernel must report the overflow uid rather than mapping "
         "the caller's real uid - this is why the parent must write "
         "uid_map before letting the child proceed";

  // Reap the child so the test does not leave a zombie behind. The exit
  // status carries nothing this test cares about, but the reap itself must
  // succeed - a failure here means the child was never ours to wait on.
  EXPECT_TRUE(wait_for(r->pid)) << "failed to reap the container process";
}

// ---------------------------------------------------------------------------
// run_init_shim reaps a reparented orphan grandchild, not just its tracked
// child.
// ---------------------------------------------------------------------------

struct MiddleChildArgs {
  int report_fd;
  unsigned grandchild_sleep_us;
};

// Runs as C: forks G (a plain fork() - safe here because by the time C's
// child_fn body runs, we are a fully independent, single-threaded process; a
// fork() call itself takes no lock and allocates nothing, so it does not
// carry the malloc-deadlock hazard child_fn otherwise avoids), reports G's
// pid to the test, then returns immediately - orphaning G to whichever
// ancestor has PR_SET_CHILD_SUBREAPER set.
int orphan_middle_child(void* arg) {
  auto* a = static_cast<MiddleChildArgs*>(arg);
  ::pid_t g = ::fork();
  if (g == 0) {
    ::usleep(a->grandchild_sleep_us);
    _exit(0);
  }
  (void)::write(a->report_fd, &g, sizeof(g));
  return 0;
}

int tracked_sleep_child(void* arg) {
  auto* us = static_cast<unsigned*>(arg);
  ::usleep(*us);
  return 9;
}

bool proc_entry_exists(::pid_t pid) {
  struct ::stat st {};
  return ::stat(("/proc/" + std::to_string(pid)).c_str(), &st) == 0;
}

TEST(InitShim, ReapsReparentedOrphanWhileTrackingItsOwnChild) {
  MC_REQUIRE_ROOT();

  sigset_t saved_mask;
  ASSERT_EQ(::sigprocmask(SIG_SETMASK, nullptr, &saved_mask), 0);
  ASSERT_EQ(::prctl(PR_SET_CHILD_SUBREAPER, 1), 0)
      << "prctl(PR_SET_CHILD_SUBREAPER): " << std::strerror(errno);

  Expected<Pipe> report_r = Pipe::create();
  ASSERT_TRUE(report_r.has_value()) << report_r.error().message();
  Pipe report = std::move(report_r).value();

  // The grandchild sleeps far less than the tracked child, so by the time
  // run_init_shim finally sees the tracked child exit and returns, the
  // grandchild's own SIGCHLD will already have been drained by the shim's
  // reap-everything-reapable loop.
  MiddleChildArgs mid_args{report.write_end.get(), 150 * 1000};

  CloneRequest creq;
  creq.flags = 0;  // plain fork-equivalent, no namespace/privilege needed
  creq.exit_signal = SIGCHLD;

  Expected<CloneResult> middle =
      clone_process(creq, &orphan_middle_child, &mid_args);
  ASSERT_TRUE(middle.has_value()) << middle.error().message();

  report.write_end.reset();
  ::pid_t grandchild_pid = -1;
  ssize_t n =
      ::read(report.read_end.get(), &grandchild_pid, sizeof(grandchild_pid));
  ASSERT_EQ(n, static_cast<ssize_t>(sizeof(grandchild_pid)));
  ASSERT_GT(grandchild_pid, 0);

  unsigned tracked_sleep_us = 400 * 1000;
  Expected<CloneResult> tracked =
      clone_process(creq, &tracked_sleep_child, &tracked_sleep_us);
  ASSERT_TRUE(tracked.has_value()) << tracked.error().message();

  InitShimOptions opts;
  opts.forward_signals = true;
  opts.reap_orphans = true;

  Expected<ExitStatus> status = run_init_shim(tracked->pid, opts);

  // Restore state before any further assertions / test teardown.
  ::sigprocmask(SIG_SETMASK, &saved_mask, nullptr);
  ::prctl(PR_SET_CHILD_SUBREAPER, 0);

  ASSERT_TRUE(status.has_value()) << status.error().message();
  EXPECT_TRUE(status->exited);
  EXPECT_EQ(status->code, 9);

  // The grandchild should already be gone; poll briefly as a safety margin
  // against scheduling jitter rather than asserting instantaneously.
  for (int i = 0; i < 100 && proc_entry_exists(grandchild_pid); ++i) {
    ::usleep(20 * 1000);
  }
  EXPECT_FALSE(proc_entry_exists(grandchild_pid))
      << "grandchild pid " << grandchild_pid
      << " was reparented to the subreaper but run_init_shim never reaped "
         "it - it is stuck as a zombie";
}

// ---------------------------------------------------------------------------
// clone3 with an obviously-bad flag combination: a clean, decoded Error.
// ---------------------------------------------------------------------------

int unreachable_child(void*) {
  return 0;
}

TEST(CloneProcess, BadFlagComboProducesCleanDecodedError) {
  MC_REQUIRE_ROOT();

  CloneRequest req;
  // Documented-invalid per clone(2)/clone3(2): CLONE_NEWPID cannot be
  // combined with CLONE_THREAD (a new thread cannot join a new PID
  // namespace while still sharing the parent's thread group).
  req.flags = CLONE_NEWPID | CLONE_THREAD;
  req.exit_signal = SIGCHLD;

  Expected<CloneResult> r = clone_process(req, &unreachable_child, nullptr);
  ASSERT_FALSE(r.has_value())
      << "CLONE_NEWPID|CLONE_THREAD is documented-invalid and must fail";

  const std::string msg = r.error().message();
  EXPECT_NE(msg.find("clone3"), std::string::npos) << msg;
  EXPECT_NE(msg.find("CLONE_NEWPID"), std::string::npos) << msg;
  EXPECT_NE(msg.find("CLONE_THREAD"), std::string::npos) << msg;
}

// ---------------------------------------------------------------------------
// namespace_join smoke test: open + join a namespace this process already
// belongs to (still needs CAP_SYS_ADMIN to call setns() at all).
// ---------------------------------------------------------------------------

TEST(NamespaceJoin, OpenAndJoinOwnUtsNamespaceSucceeds) {
  MC_REQUIRE_ROOT();

  Expected<Fd> ns = open_namespace(::getpid(), NsType::Uts);
  ASSERT_TRUE(ns.has_value()) << ns.error().message();
  EXPECT_TRUE(ns->valid());

  Expected<void> joined = join_namespace(ns.value(), NsType::Uts);
  EXPECT_TRUE(joined.has_value())
      << (joined.has_value() ? std::string() : joined.error().message());
}

// ---------------------------------------------------------------------------
// run_init_shim forwards a signal it receives to the tracked child.
//
// This is the other half of the shim's reason to exist. Inside a PID
// namespace the kernel does not apply default signal dispositions to PID 1,
// so `minicontainer stop` sending SIGTERM would otherwise be dropped on the
// floor and every stop would cost the full SIGKILL timeout.
//
// The forward is `kill(-child, signo)` - to the child's process GROUP, so
// that an entrypoint like `sh -c "sleep 100"` takes its children down with
// it. A group with that id only exists if the child leads it, and a clone3()
// child inherits its parent's pgid rather than starting a group of its own,
// so run_init_shim has to establish the group itself. If it stops doing that,
// the forward silently targets a non-existent group and this test catches it.
// ---------------------------------------------------------------------------

struct SignalHelperArgs {
  ::pid_t shim_pid;      // who to send the signal we want forwarded
  ::pid_t watchdog_pid;  // killed directly if forwarding never happens
  unsigned delay_us;
  unsigned watchdog_us;
};

// Waits, signals the shim, then - only if the shim failed to pass it on -
// kills the tracked child directly so a broken forward shows up as a failed
// assertion rather than as a hung test.
int signal_helper_child(void* arg) {
  auto* a = static_cast<SignalHelperArgs*>(arg);
  ::usleep(a->delay_us);
  ::kill(a->shim_pid, SIGTERM);
  ::usleep(a->watchdog_us);
  ::kill(a->watchdog_pid, SIGKILL);
  return 0;
}

TEST(InitShim, ForwardsSignalToTrackedChildsProcessGroup) {
  MC_REQUIRE_ROOT();

  sigset_t saved_mask;
  ASSERT_EQ(::sigprocmask(SIG_SETMASK, nullptr, &saved_mask), 0);

  CloneRequest creq;
  creq.flags = 0;  // plain fork-equivalent; no namespace needed
  creq.exit_signal = SIGCHLD;

  // The tracked child just blocks. It is NOT PID 1 here (no CLONE_NEWPID), so
  // the kernel's default SIGTERM disposition applies and a forwarded SIGTERM
  // is enough to terminate it - which is precisely the observable effect.
  Expected<CloneResult> tracked = clone_process(creq, &pause_child, nullptr);
  ASSERT_TRUE(tracked.has_value()) << tracked.error().message();

  SignalHelperArgs helper_args{::getpid(), tracked->pid, 150 * 1000,
                               2000 * 1000};
  Expected<CloneResult> helper =
      clone_process(creq, &signal_helper_child, &helper_args);
  ASSERT_TRUE(helper.has_value()) << helper.error().message();

  InitShimOptions opts;
  opts.forward_signals = true;
  opts.reap_orphans = true;

  Expected<ExitStatus> status = run_init_shim(tracked->pid, opts);

  ::sigprocmask(SIG_SETMASK, &saved_mask, nullptr);

  ASSERT_TRUE(status.has_value()) << status.error().message();
  EXPECT_TRUE(status->signaled)
      << "tracked child should have died to the forwarded signal, but it "
      << status->describe();
  EXPECT_EQ(status->signal, SIGTERM)
      << "expected the SIGTERM sent to the shim to reach the child; got "
      << status->describe()
      << ". SIGKILL here means the watchdog had to step in because the "
         "forward never arrived.";
}

}  // namespace
}  // namespace mc
