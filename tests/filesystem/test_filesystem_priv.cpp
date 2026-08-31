// SPDX-License-Identifier: MIT
//
// MiniContainer - filesystem module PRIVILEGED integration tests.
//
// The filesystem step functions (bind rootfs, mount /proc and /dev, create
// device nodes, pivot_root, detach the old root) had been exercised many
// times over by the point this file was written - every `minicontainer run`
// this project has ever done goes through exactly this code - but never by an
// automated test that runs under `ctest`. This file closes that gap.
//
// HOST SAFETY
// -----------
// Every test runs inside a scratch rootfs under a fresh CLONE_NEWNS: pivoting
// root and unmounting the old one only ever happen in that child's own
// PRIVATE mount namespace, never the test process's or the host's. The
// scratch rootfs lives under a mkdtemp'd directory that TearDown removes
// unconditionally.
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <sched.h>
#include <signal.h>
#include <unistd.h>

#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <string>

#include "minicontainer/container.h"
#include "minicontainer/errors.h"
#include "minicontainer/filesystem.h"
#include "minicontainer/process.h"

#include <gtest/gtest.h>

#define MC_REQUIRE_ROOT()              \
  do {                                 \
    if (::geteuid() != 0) {            \
      GTEST_SKIP() << "requires root"; \
    }                                  \
  } while (0)

namespace mc {
namespace {

bool ensure_dir(const std::string& path) {
  return ::mkdir(path.c_str(), 0755) == 0 || errno == EEXIST;
}

// Everything the child needs, built by the parent before clone() - the same
// shape production uses, just without container.h's arena machinery, since
// every string here is a parent-owned std::string that stays alive for the
// clone3()'d child's independent copy-on-write view of this memory.
struct FsChildArgs {
  ChildContext ctx;
  int sync_read_fd = -1;
  int result_write_fd = -1;
};

struct FsChildResult {
  bool ok = false;
  Op failed_op = Op::None;
  int err = 0;
  bool proc_mounted = false;
  bool dev_null_is_char_device = false;
  bool old_root_gone = false;
  bool workdir_applied = false;
};

ChildStatus run_or_report(ChildStatus (*step)(const ChildContext&),
                          const ChildContext& ctx, FsChildResult& result) {
  const ChildStatus st = step(ctx);
  if (!st.ok()) {
    result.ok = false;
    result.failed_op = st.op;
    result.err = st.err;
  }
  return st;
}

int fs_child_fn(void* raw) noexcept {
  auto* a = static_cast<FsChildArgs*>(raw);

  char go = 0;
  if (::read(a->sync_read_fd, &go, 1) != 1 || go != 'G') {
    ::_exit(126);
  }

  FsChildResult result;
  result.ok = true;

  // The real step table's own order for this slice: private propagation,
  // bind the rootfs onto itself (pivot_root requires new_root to be a mount
  // point), the pseudo-filesystems, then the pivot and detach.
  ChildStatus st;
#define MC_STEP(fn)                                             \
  st = run_or_report(&fn, a->ctx, result);                      \
  if (!st.ok()) {                                               \
    (void)::write(a->result_write_fd, &result, sizeof(result)); \
    ::_exit(1);                                                 \
  }

  MC_STEP(step_make_root_private)
  MC_STEP(step_bind_rootfs)
  MC_STEP(step_mount_proc)
  MC_STEP(step_mount_dev)
  MC_STEP(step_create_device_nodes)
  MC_STEP(step_mount_tmp)
  MC_STEP(step_pivot_root)
  MC_STEP(step_umount_old_root)
  MC_STEP(step_set_working_dir)
#undef MC_STEP

  // Verification, from INSIDE the new root: proves the steps did what they
  // claim, not just that they returned success.
  struct ::stat st_proc {};
  result.proc_mounted = ::stat("/proc/version", &st_proc) == 0;

  struct ::stat st_null {};
  result.dev_null_is_char_device =
      ::stat("/dev/null", &st_null) == 0 && S_ISCHR(st_null.st_mode);

  struct ::stat st_old {};
  result.old_root_gone = ::stat("/.oldroot", &st_old) != 0 && errno == ENOENT;

  char cwd[256] = {};
  result.workdir_applied =
      ::getcwd(cwd, sizeof(cwd)) != nullptr && std::strcmp(cwd, "/tmp") == 0;

  (void)::write(a->result_write_fd, &result, sizeof(result));
  ::_exit(0);
}

// Recursively removes the scratch rootfs. Best-effort: this is test cleanup,
// not production code, and a leftover empty-ish tmp directory is harmless.
void remove_tree(const std::string& path) {
  const ::pid_t pid = ::fork();
  if (pid == 0) {
    ::execlp("rm", "rm", "-rf", path.c_str(), static_cast<char*>(nullptr));
    ::_exit(127);
  }
  if (pid > 0) {
    int status = 0;
    ::waitpid(pid, &status, 0);
  }
}

class FilesystemPriv : public ::testing::Test {
 protected:
  void SetUp() override {
    char tmpl[] = "/tmp/mc-fs-test-XXXXXX";
    const char* dir = ::mkdtemp(tmpl);
    ASSERT_NE(dir, nullptr) << "mkdtemp: " << std::strerror(errno);
    rootfs_ = dir;

    ASSERT_TRUE(ensure_dir(rootfs_ + "/proc"));
    ASSERT_TRUE(ensure_dir(rootfs_ + "/sys"));
    ASSERT_TRUE(ensure_dir(rootfs_ + "/dev"));
    ASSERT_TRUE(ensure_dir(rootfs_ + "/dev/pts"));
    ASSERT_TRUE(ensure_dir(rootfs_ + "/tmp"));
  }

  void TearDown() override {
    if (!rootfs_.empty()) {
      remove_tree(rootfs_);
    }
  }

  std::string rootfs_;
};

}  // namespace

// ---------------------------------------------------------------------------
// The full slice: bind, mount, pivot, detach, chdir - run against a real
// scratch rootfs in a real (but private) mount namespace, verified from
// inside the result.
// ---------------------------------------------------------------------------
TEST_F(FilesystemPriv, FullMountAndPivotSequenceIsolatesARealRootfs) {
  MC_REQUIRE_ROOT();

  Expected<Pipe> sync_pipe = Pipe::create();
  ASSERT_TRUE(sync_pipe) << sync_pipe.error().message();
  Expected<Pipe> result_pipe = Pipe::create();
  ASSERT_TRUE(result_pipe) << result_pipe.error().message();

  auto args = std::make_unique<FsChildArgs>();
  args->sync_read_fd = sync_pipe->read_end.get();
  args->result_write_fd = result_pipe->write_end.get();
  args->ctx.rootfs = rootfs_.c_str();
  args->ctx.working_dir = "/tmp";
  args->ctx.mount_sys = false;  // scratch rootfs need not model every mount
  args->ctx.mount_devpts = false;
  args->ctx.readonly_rootfs = false;

  CloneRequest req;
  // CLONE_NEWNS is the one that matters for host safety: everything this
  // sequence does to the mount table happens in a namespace of its own.
  req.flags = CLONE_NEWNS;
  req.exit_signal = SIGCHLD;
  Expected<CloneResult> cloned = clone_process(req, &fs_child_fn, args.get());
  ASSERT_TRUE(cloned) << cloned.error().message();

  ASSERT_TRUE(sync_pipe->write_byte('G'));
  sync_pipe->write_end.reset();

  FsChildResult result{};
  const ssize_t n =
      ::read(result_pipe->read_end.get(), &result, sizeof(result));
  ASSERT_EQ(n, static_cast<ssize_t>(sizeof(result)));

  int status = 0;
  ::waitpid(cloned->pid, &status, 0);

  ASSERT_TRUE(result.ok) << "step " << op_name(result.failed_op)
                         << " failed with errno " << result.err << " ("
                         << std::strerror(result.err) << ")";
  EXPECT_TRUE(result.proc_mounted)
      << "/proc/version was not readable after step_mount_proc + pivot_root - "
         "the new root's /proc mount did not take";
  EXPECT_TRUE(result.dev_null_is_char_device)
      << "/dev/null was not a character device after "
         "step_create_device_nodes - mknod either did not run or targeted "
         "the wrong path post-pivot";
  EXPECT_TRUE(result.old_root_gone)
      << "/.oldroot still existed after step_umount_old_root - the old root "
         "was not fully detached, which means the isolation is not real";
  EXPECT_TRUE(result.workdir_applied)
      << "cwd was not /tmp after step_set_working_dir - either it ran before "
         "the pivot (resolving against the wrong tree) or did not run";
}

}  // namespace mc
