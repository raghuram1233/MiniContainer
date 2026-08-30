// SPDX-License-Identifier: MIT
//
// MiniContainer - process layer unit tests. No root required: these exercise
// Fd/Pipe primitives, ExitStatus formatting, ns_proc_name, and a plain
// clone_process(flags=0) (a bare fork - creates no namespace, needs no
// privilege).

#include <fcntl.h>
#include <signal.h>
#include <unistd.h>

#include <optional>
#include <string>

#include "minicontainer/errors.h"
#include "minicontainer/process.h"

#include <gtest/gtest.h>

namespace mc {
namespace {

// ---------------------------------------------------------------------------
// Fd
// ---------------------------------------------------------------------------

TEST(Fd, DefaultIsInvalid) {
  Fd f;
  EXPECT_FALSE(f.valid());
  EXPECT_FALSE(static_cast<bool>(f));
  EXPECT_EQ(f.get(), -1);
}

TEST(Fd, MoveConstructTransfersOwnership) {
  Pipe p = Pipe::create().value();
  int raw = p.read_end.get();
  Fd moved(std::move(p.read_end));
  EXPECT_TRUE(moved.valid());
  EXPECT_EQ(moved.get(), raw);
  EXPECT_FALSE(p.read_end.valid());  // moved-from is invalid
  EXPECT_EQ(p.read_end.get(), -1);
}

TEST(Fd, MoveAssignClosesPreviousFd) {
  Pipe a = Pipe::create().value();
  Pipe b = Pipe::create().value();
  int a_raw = a.read_end.get();
  int b_raw = b.read_end.get();
  ASSERT_NE(a_raw, b_raw);

  a.read_end = std::move(b.read_end);
  EXPECT_EQ(a.read_end.get(), b_raw);
  EXPECT_FALSE(b.read_end.valid());

  // The fd that used to belong to `a` must now be closed.
  errno = 0;
  int rc = ::fcntl(a_raw, F_GETFD);
  EXPECT_EQ(rc, -1);
  EXPECT_EQ(errno, EBADF);
}

TEST(Fd, SelfMoveAssignIsSafe) {
  Pipe p = Pipe::create().value();
  int raw = p.read_end.get();
  Fd& ref = p.read_end;
  // Self-move is exactly what this test exercises, so the compiler's warning
  // about it is correct and unwanted. Scope the suppression to this one line;
  // dropping -Wself-move tree-wide would hide the real bug it catches.
#if defined(__GNUC__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wself-move"
#endif
  ref = std::move(ref);  // NOLINT(clang-diagnostic-self-move)
#if defined(__GNUC__)
#pragma GCC diagnostic pop
#endif
  EXPECT_EQ(p.read_end.get(), raw);
}

TEST(Fd, ReleaseGivesUpOwnershipWithoutClosing) {
  Pipe p = Pipe::create().value();
  int raw = p.read_end.release();
  EXPECT_FALSE(p.read_end.valid());
  // Still open - release() must not close it.
  EXPECT_NE(::fcntl(raw, F_GETFD), -1);
  ::close(raw);
}

TEST(Fd, ResetClosesOnlyWhenValid) {
  Fd f;
  f.reset();  // no-op on an already-invalid fd; must not touch fd -1.
  EXPECT_FALSE(f.valid());

  Pipe p = Pipe::create().value();
  int raw = p.read_end.get();
  p.read_end.reset();
  EXPECT_FALSE(p.read_end.valid());
  errno = 0;
  EXPECT_EQ(::fcntl(raw, F_GETFD), -1);
  EXPECT_EQ(errno, EBADF);
}

TEST(Fd, DoubleCloseIsSafe) {
  Pipe p = Pipe::create().value();
  int raw = p.read_end.get();
  p.read_end.reset();
  // Destructor of the (already reset) Fd runs at end of scope; explicit
  // second reset here simulates the same "close an already-closed fd" shape.
  p.read_end.reset();
  errno = 0;
  EXPECT_EQ(::fcntl(raw, F_GETFD), -1);
  EXPECT_EQ(errno, EBADF);
}

TEST(Fd, DuplicateSetsCloexec) {
  Pipe p = Pipe::create().value();
  Expected<Fd> dup = p.read_end.duplicate();
  ASSERT_TRUE(dup.has_value()) << dup.error().message();
  EXPECT_TRUE(dup->valid());
  EXPECT_NE(dup->get(), p.read_end.get());

  int flags = ::fcntl(dup->get(), F_GETFD);
  ASSERT_NE(flags, -1);
  EXPECT_TRUE(flags & FD_CLOEXEC);
}

TEST(Fd, DuplicateOfInvalidFdFails) {
  Fd f;
  Expected<Fd> dup = f.duplicate();
  EXPECT_FALSE(dup.has_value());
}

// ---------------------------------------------------------------------------
// Pipe
// ---------------------------------------------------------------------------

TEST(Pipe, CreateSetsCloexecOnBothEnds) {
  Pipe p = Pipe::create().value();
  int rflags = ::fcntl(p.read_end.get(), F_GETFD);
  int wflags = ::fcntl(p.write_end.get(), F_GETFD);
  ASSERT_NE(rflags, -1);
  ASSERT_NE(wflags, -1);
  EXPECT_TRUE(rflags & FD_CLOEXEC);
  EXPECT_TRUE(wflags & FD_CLOEXEC);
}

TEST(Pipe, RoundTripSingleByte) {
  Pipe p = Pipe::create().value();
  ASSERT_TRUE(p.write_byte('Q').has_value());
  Expected<std::optional<char>> got = p.read_byte();
  ASSERT_TRUE(got.has_value());
  ASSERT_TRUE(got->has_value());
  EXPECT_EQ(**got, 'Q');
}

TEST(Pipe, RoundTripMultipleBytesInOrder) {
  Pipe p = Pipe::create().value();
  const std::string msg = "MCER";
  for (char c : msg) {
    ASSERT_TRUE(p.write_byte(c).has_value());
  }
  std::string got;
  for (std::size_t i = 0; i < msg.size(); ++i) {
    Expected<std::optional<char>> b = p.read_byte();
    ASSERT_TRUE(b.has_value());
    ASSERT_TRUE(b->has_value());
    got.push_back(**b);
  }
  EXPECT_EQ(got, msg);
}

TEST(Pipe, ReadByteReturnsNulloptOnEof) {
  Pipe p = Pipe::create().value();
  p.write_end.reset();  // closes the write end -> EOF for the reader
  Expected<std::optional<char>> got = p.read_byte();
  ASSERT_TRUE(got.has_value()) << got.error().message();
  EXPECT_FALSE(got->has_value());
}

// ---------------------------------------------------------------------------
// ExitStatus
// ---------------------------------------------------------------------------

TEST(ExitStatus, ExitedShellCodeIsCode) {
  ExitStatus es;
  es.exited = true;
  es.code = 0;
  EXPECT_EQ(es.to_shell_code(), 0);

  es.code = 42;
  EXPECT_EQ(es.to_shell_code(), 42);
}

TEST(ExitStatus, SignaledShellCodeIs128PlusSignal) {
  ExitStatus es;
  es.signaled = true;
  es.signal = SIGTERM;
  EXPECT_EQ(es.to_shell_code(), 128 + SIGTERM);
}

TEST(ExitStatus, DescribeExited) {
  ExitStatus es;
  es.exited = true;
  es.code = 0;
  EXPECT_EQ(es.describe(), "exited with code 0");
}

TEST(ExitStatus, DescribeSignaled) {
  ExitStatus es;
  es.signaled = true;
  es.signal = SIGTERM;
  EXPECT_EQ(es.describe(), "killed by SIGTERM");
}

// ---------------------------------------------------------------------------
// ns_proc_name
// ---------------------------------------------------------------------------

TEST(NsProcName, MapsToKernelProcNames) {
  EXPECT_STREQ(ns_proc_name(NsType::Pid), "pid");
  EXPECT_STREQ(ns_proc_name(NsType::Uts), "uts");
  EXPECT_STREQ(ns_proc_name(NsType::Mount), "mnt");  // the odd one out
  EXPECT_STREQ(ns_proc_name(NsType::Ipc), "ipc");
  EXPECT_STREQ(ns_proc_name(NsType::Net), "net");
  EXPECT_STREQ(ns_proc_name(NsType::User), "user");
  EXPECT_STREQ(ns_proc_name(NsType::Cgroup), "cgroup");
  EXPECT_STREQ(ns_proc_name(NsType::Time), "time");
}

TEST(NsTypeName, IsHumanReadable) {
  EXPECT_STREQ(ns_type_name(NsType::Mount), "Mount");
  EXPECT_STREQ(ns_type_name(NsType::Pid), "PID");
}

// ---------------------------------------------------------------------------
// clone_process(flags=0) - a bare fork, no privilege required.
// ---------------------------------------------------------------------------

int child_exit_42(void*) {
  return 42;
}

TEST(CloneProcess, PlainForkChildExitCodeIsObservedByParent) {
  CloneRequest req;
  req.flags = 0;
  req.exit_signal = SIGCHLD;

  Expected<CloneResult> r = clone_process(req, &child_exit_42, nullptr);
  ASSERT_TRUE(r.has_value()) << r.error().message();
  EXPECT_GT(r->pid, 0);
  EXPECT_FALSE(r->pidfd.valid());  // CLONE_PIDFD was not requested

  Expected<ExitStatus> status = wait_for(r->pid);
  ASSERT_TRUE(status.has_value()) << status.error().message();
  EXPECT_TRUE(status->exited);
  EXPECT_FALSE(status->signaled);
  EXPECT_EQ(status->code, 42);
  EXPECT_EQ(status->to_shell_code(), 42);
}

int child_raise_sigkill(void*) {
  ::raise(SIGKILL);
  return 1;  // unreachable
}

TEST(CloneProcess, PlainForkChildKilledBySignalReportsSignaled) {
  CloneRequest req;
  req.flags = 0;
  req.exit_signal = SIGCHLD;

  Expected<CloneResult> r = clone_process(req, &child_raise_sigkill, nullptr);
  ASSERT_TRUE(r.has_value()) << r.error().message();

  Expected<ExitStatus> status = wait_for(r->pid);
  ASSERT_TRUE(status.has_value()) << status.error().message();
  EXPECT_FALSE(status->exited);
  EXPECT_TRUE(status->signaled);
  EXPECT_EQ(status->signal, SIGKILL);
  EXPECT_EQ(status->to_shell_code(), 128 + SIGKILL);
}

TEST(TryWait, ReturnsNulloptWhileChildIsAlive) {
  CloneRequest req;
  req.flags = 0;
  req.exit_signal = SIGCHLD;

  // Child sleeps briefly so the parent can observe it as still-running.
  static int (*sleep_fn)(void*) = [](void*) -> int {
    ::usleep(200 * 1000);
    return 7;
  };

  Expected<CloneResult> r = clone_process(req, sleep_fn, nullptr);
  ASSERT_TRUE(r.has_value()) << r.error().message();

  Expected<std::optional<ExitStatus>> early = try_wait(r->pid);
  ASSERT_TRUE(early.has_value()) << early.error().message();
  EXPECT_FALSE(early->has_value());

  Expected<ExitStatus> final_status = wait_for(r->pid);
  ASSERT_TRUE(final_status.has_value()) << final_status.error().message();
  EXPECT_EQ(final_status->code, 7);
}

}  // namespace
}  // namespace mc
