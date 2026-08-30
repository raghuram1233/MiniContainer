// SPDX-License-Identifier: MIT
//
// Unit tests for src/core/errors.cpp. Run without root.

#include <cerrno>
#include <cstring>
#include <set>
#include <stdexcept>
#include <string>
#include <vector>

#include "minicontainer/errors.h"

#include <gtest/gtest.h>

// ---------------------------------------------------------------------------
// Op table: every enumerator has a non-empty, distinct description and name.
// ---------------------------------------------------------------------------
TEST(OpTableTest, EveryOpHasNonEmptyDistinctDescriptionAndName) {
  const std::vector<mc::Op> ops = {
#define MC_OP_TEST_VAL(name, desc) mc::Op::name,
      MC_OP_LIST(MC_OP_TEST_VAL)
#undef MC_OP_TEST_VAL
  };

  std::set<std::string> descriptions;
  std::set<std::string> names;
  for (mc::Op op : ops) {
    const char* d = mc::op_description(op);
    const char* n = mc::op_name(op);
    ASSERT_NE(d, nullptr);
    ASSERT_NE(n, nullptr);
    EXPECT_GT(std::strlen(d), 0u);
    EXPECT_GT(std::strlen(n), 0u);
    EXPECT_TRUE(descriptions.insert(d).second)
        << "duplicate description: " << d;
    EXPECT_TRUE(names.insert(n).second) << "duplicate name: " << n;
  }
}

// ---------------------------------------------------------------------------
// Error::message() exact-string shapes.
// ---------------------------------------------------------------------------
TEST(ErrorMessageTest, SyscallError) {
  mc::Error e = mc::Error::syscall(mc::Op::CloneProcess, "clone3", EPERM,
                                   "CLONE_NEWPID|CLONE_NEWUSER");
  EXPECT_EQ(e.message(),
            "Failed to create container process: "
            "clone3(CLONE_NEWPID|CLONE_NEWUSER): "
            "Operation not permitted (EPERM)");
}

TEST(ErrorMessageTest, InvalidConfigError) {
  mc::Error e =
      mc::Error::invalid(mc::Op::ValidateRootfs, "/rootfs has no /bin/sh");
  EXPECT_EQ(e.message(),
            "Failed to validate root filesystem: /rootfs has no /bin/sh");
}

TEST(ErrorMessageTest, ErrorWithContext) {
  mc::Error e = mc::Error::invalid(mc::Op::ValidateConfig, "bad name")
                    .with_context("id=abc123");
  EXPECT_EQ(e.message(),
            "Failed to validate container configuration: bad name [id=abc123]");
}

TEST(ErrorMessageTest, ChildOriginatedError) {
  mc::ChildErrorWire wire{};
  wire.magic = mc::kChildErrorMagic;
  wire.op = static_cast<std::uint16_t>(mc::Op::MountProc);
  wire.err = ENOENT;
  const std::string detail = "/proc -> /rootfs/proc";
  wire.detail_len = static_cast<std::uint16_t>(detail.size());
  std::memcpy(wire.detail, detail.data(), detail.size());

  mc::Error e = mc::Error::from_child(wire);
  EXPECT_TRUE(e.from_child_process());
  EXPECT_EQ(e.message(),
            "container process: Failed to mount /proc: "
            "/proc -> /rootfs/proc: No such file or directory (ENOENT)");
}

TEST(ErrorMessageTest, NoDanglingPunctuationWhenPartsAreEmpty) {
  mc::Error e = mc::Error::syscall(mc::Op::Internal, "somecall", 0, "");
  // No detail, no errno -> just "Failed to <op>: somecall" with no "()" and
  // no trailing colon/space artifacts.
  EXPECT_EQ(e.message(),
            "Failed to perform internal runtime operation: somecall");
  EXPECT_EQ(e.message().find("()"), std::string::npos);
}

// ---------------------------------------------------------------------------
// errno_name.
// ---------------------------------------------------------------------------
TEST(ErrnoNameTest, KnownValues) {
  EXPECT_STREQ(mc::errno_name(EPERM), "EPERM");
  EXPECT_STREQ(mc::errno_name(EACCES), "EACCES");
  EXPECT_STREQ(mc::errno_name(ENOENT), "ENOENT");
  EXPECT_STREQ(mc::errno_name(EEXIST), "EEXIST");
  EXPECT_STREQ(mc::errno_name(EINVAL), "EINVAL");
  EXPECT_STREQ(mc::errno_name(ENOSPC), "ENOSPC");
  EXPECT_STREQ(mc::errno_name(EBUSY), "EBUSY");
  EXPECT_STREQ(mc::errno_name(ENOTDIR), "ENOTDIR");
  EXPECT_STREQ(mc::errno_name(EISDIR), "EISDIR");
  EXPECT_STREQ(mc::errno_name(ENOMEM), "ENOMEM");
  EXPECT_STREQ(mc::errno_name(EAGAIN), "EAGAIN");
  EXPECT_STREQ(mc::errno_name(ECHILD), "ECHILD");
  EXPECT_STREQ(mc::errno_name(ESRCH), "ESRCH");
  EXPECT_STREQ(mc::errno_name(EMFILE), "EMFILE");
  EXPECT_STREQ(mc::errno_name(ENFILE), "ENFILE");
  EXPECT_STREQ(mc::errno_name(EXDEV), "EXDEV");
  EXPECT_STREQ(mc::errno_name(ELOOP), "ELOOP");
  EXPECT_STREQ(mc::errno_name(ENAMETOOLONG), "ENAMETOOLONG");
  EXPECT_STREQ(mc::errno_name(ENOSYS), "ENOSYS");
  EXPECT_STREQ(mc::errno_name(EUSERS), "EUSERS");
  EXPECT_STREQ(mc::errno_name(EROFS), "EROFS");
  EXPECT_STREQ(mc::errno_name(EMLINK), "EMLINK");
  EXPECT_STREQ(mc::errno_name(ERANGE), "ERANGE");
  EXPECT_STREQ(mc::errno_name(EDOM), "EDOM");
  EXPECT_STREQ(mc::errno_name(EPIPE), "EPIPE");
  EXPECT_STREQ(mc::errno_name(EINTR), "EINTR");
  // ENOTSUP and EOPNOTSUPP alias to the same integer on Linux; whichever name
  // wins, it must be non-empty.
  EXPECT_STRNE(mc::errno_name(EOPNOTSUPP), "");
  EXPECT_STRNE(mc::errno_name(ENOTSUP), "");
}

TEST(ErrnoNameTest, ZeroAndUnknownReturnEmpty) {
  EXPECT_STREQ(mc::errno_name(0), "");
  EXPECT_STREQ(mc::errno_name(999999), "");
}

// ---------------------------------------------------------------------------
// Expected<T> / Expected<void>.
// ---------------------------------------------------------------------------
TEST(ExpectedTest, SuccessValue) {
  mc::Expected<int> e = 42;
  ASSERT_TRUE(e.has_value());
  EXPECT_TRUE(static_cast<bool>(e));
  EXPECT_EQ(e.value(), 42);
  EXPECT_EQ(*e, 42);
}

TEST(ExpectedTest, FailureValue) {
  mc::Expected<int> e = mc::Err(mc::Error::invalid(mc::Op::Internal, "bad"));
  ASSERT_FALSE(e.has_value());
  EXPECT_FALSE(static_cast<bool>(e));
  EXPECT_EQ(e.error().op(), mc::Op::Internal);
}

TEST(ExpectedTest, VoidSuccess) {
  mc::Expected<void> e = mc::Ok();
  EXPECT_TRUE(e.has_value());
}

TEST(ExpectedTest, VoidFailure) {
  mc::Expected<void> e = mc::Err(mc::Error::invalid(mc::Op::Internal, "bad"));
  EXPECT_FALSE(e.has_value());
}

TEST(ExpectedTest, ValueOr) {
  mc::Expected<int> ok = 5;
  mc::Expected<int> bad = mc::Err(mc::Error::invalid(mc::Op::Internal, "x"));
  EXPECT_EQ(ok.value_or(99), 5);
  EXPECT_EQ(bad.value_or(99), 99);
}

namespace {
mc::Expected<int> mc_try_helper(bool succeed) {
  mc::Expected<int> inner =
      succeed ? mc::Expected<int>(7)
              : mc::Expected<int>(
                    mc::Err(mc::Error::invalid(mc::Op::Internal, "fail")));
  int v = MC_TRY(inner);
  return v * 2;
}

mc::Expected<void> mc_check_helper(bool succeed) {
  mc::Expected<void> inner =
      succeed ? mc::Ok()
              : mc::Expected<void>(
                    mc::Err(mc::Error::invalid(mc::Op::Internal, "fail")));
  MC_CHECK(inner);
  return mc::Ok();
}
}  // namespace

TEST(ExpectedTest, McTryPropagatesSuccess) {
  auto r = mc_try_helper(true);
  ASSERT_TRUE(r.has_value());
  EXPECT_EQ(r.value(), 14);
}

TEST(ExpectedTest, McTryPropagatesFailure) {
  auto r = mc_try_helper(false);
  ASSERT_FALSE(r.has_value());
  EXPECT_EQ(r.error().op(), mc::Op::Internal);
}

TEST(ExpectedTest, McCheckPropagatesSuccess) {
  EXPECT_TRUE(mc_check_helper(true).has_value());
}

TEST(ExpectedTest, McCheckPropagatesFailure) {
  EXPECT_FALSE(mc_check_helper(false).has_value());
}

// ---------------------------------------------------------------------------
// Rollback.
// ---------------------------------------------------------------------------
TEST(RollbackTest, RunsInReverseOrder) {
  std::vector<int> order;
  mc::Rollback rb;
  rb.push("first", [&] { order.push_back(1); });
  rb.push("second", [&] { order.push_back(2); });
  rb.push("third", [&] { order.push_back(3); });
  rb.run();

  ASSERT_EQ(order.size(), 3u);
  EXPECT_EQ(order[0], 3);
  EXPECT_EQ(order[1], 2);
  EXPECT_EQ(order[2], 1);
}

TEST(RollbackTest, DismissPreventsRun) {
  std::vector<int> order;
  mc::Rollback rb;
  rb.push("x", [&] { order.push_back(1); });
  rb.dismiss();
  rb.run();
  EXPECT_TRUE(order.empty());
}

TEST(RollbackTest, ThrowingUndoDoesNotEscapeRun) {
  std::vector<int> order;
  mc::Rollback rb;
  rb.push("a", [&] { order.push_back(1); });
  rb.push("throws", [&] { throw std::runtime_error("boom"); });
  rb.push("c", [&] { order.push_back(3); });

  EXPECT_NO_THROW(rb.run());
  ASSERT_EQ(order.size(), 2u);
  EXPECT_EQ(order[0], 3);
  EXPECT_EQ(order[1], 1);
}

TEST(RollbackTest, RunClearsListSoSecondRunIsNoOp) {
  int calls = 0;
  mc::Rollback rb;
  rb.push("x", [&] { ++calls; });
  rb.run();
  EXPECT_EQ(calls, 1);
  EXPECT_EQ(rb.size(), 0u);
  rb.run();
  EXPECT_EQ(calls, 1);
}

TEST(RollbackTest, DestructorRunsUnfinishedActions) {
  std::vector<int> order;
  {
    mc::Rollback rb;
    rb.push("x", [&] { order.push_back(42); });
  }
  ASSERT_EQ(order.size(), 1u);
  EXPECT_EQ(order[0], 42);
}
