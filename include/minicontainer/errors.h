// SPDX-License-Identifier: MIT
//
// MiniContainer - Tier 0 foundation: error model, Expected, rollback ledger.
//
// WHY THIS FILE EXISTS
// --------------------
// A container runtime fails in a hundred privileged ways, and "error" is a
// useless thing to print when it does. Every failure here carries: which
// high-level operation was attempted, which syscall implemented it, the exact
// flags passed, and the errno. That turns
//
//     error
//
// into
//
//     Failed to create container process: clone3(CLONE_NEWPID|CLONE_NEWUSER):
//     Operation not permitted (EPERM)
//
// TWO ERROR CHANNELS, AND WHY
// ---------------------------
// The parent uses Expected<T> + Error, which allocates (std::string).
//
// The CHILD, after clone(), must not allocate. If another thread held the
// malloc lock at the instant of clone(), the child's allocator is permanently
// wedged and the next allocation deadlocks forever. The child therefore uses
// ChildStatus (a POD) and reports failure by writing a fixed-size
// ChildErrorWire over an O_CLOEXEC pipe.
//
// The pipe's CLOEXEC is load-bearing: a successful execve() closes it, so the
// parent reading EOF *is* the success signal. No extra handshake is required,
// and there is no window in which a failure could be mistaken for success.
//
// This header is FROZEN. Changing it is a coordination event that pauses all
// parallel work, because every module compiles against it.
#pragma once

#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <functional>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>
#include <variant>
#include <vector>

namespace mc {

// ---------------------------------------------------------------------------
// Op - the high-level operation that failed.
//
// Declared as an X-macro so the enumerator and its human description can never
// drift apart. The child-setup ops appear in execution order; that order is
// mirrored by the step table in src/container/container_steps.cpp.
// ---------------------------------------------------------------------------
#define MC_OP_LIST(X)                                                       \
  X(None, "no operation")                                                   \
  /* --- configuration / preflight (parent) --- */                          \
  X(ParseArgs, "parse command line")                                        \
  X(ParseConfig, "parse container configuration")                           \
  X(ValidateConfig, "validate container configuration")                     \
  X(ValidateRootfs, "validate root filesystem")                             \
  X(Preflight, "check kernel feature support")                              \
  /* --- state store (parent) --- */                                        \
  X(CreateStateDir, "create container state directory")                     \
  X(WriteState, "write container state")                                    \
  X(ReadState, "read container state")                                      \
  X(RemoveState, "remove container state")                                  \
  X(LockState, "lock container state")                                      \
  /* --- cgroup v2 (parent) --- */                                          \
  X(DetectCgroup, "detect cgroup v2 hierarchy")                             \
  X(EnableController, "enable cgroup controllers")                          \
  X(CreateCgroup, "create cgroup")                                          \
  X(WriteCgroupLimit, "apply cgroup resource limit")                        \
  X(AttachCgroup, "attach process to cgroup")                               \
  X(ReadCgroupStat, "read cgroup statistics")                               \
  X(RemoveCgroup, "remove cgroup")                                          \
  /* --- process creation (parent) --- */                                   \
  X(CreatePipe, "create synchronisation pipe")                              \
  X(CloneProcess, "create container process")                               \
  X(WriteUidMap, "write UID map")                                           \
  X(WriteGidMap, "write GID map")                                           \
  X(DenySetgroups, "deny setgroups in user namespace")                      \
  X(SyncHandshake, "synchronise with container process")                    \
  X(WaitChild, "wait for container process")                                \
  X(SignalChild, "signal container process")                                \
  /* --- networking (parent side, host netns) --- */                        \
  X(CreateBridge, "create bridge interface")                                \
  X(CreateVeth, "create veth pair")                                         \
  X(MoveVethToNetns, "move veth peer into container network namespace")     \
  X(AttachToBridge, "attach veth to bridge")                                \
  X(ConfigureNat, "configure NAT masquerading")                             \
  X(ConfigurePortMap, "configure port forwarding")                          \
  X(TeardownNetwork, "tear down container network")                         \
  /* --- child setup, in execution order (post-clone, no allocation) --- */ \
  X(ChildSetup, "initialise container process")                             \
  X(SetHostname, "set container hostname")                                  \
  X(MakeRootPrivate, "make mount propagation private")                      \
  X(BindRootfs, "bind-mount root filesystem")                               \
  X(MountProc, "mount /proc")                                               \
  X(MountSys, "mount /sys")                                                 \
  X(MountDev, "mount /dev")                                                 \
  X(CreateDeviceNode, "create device node")                                 \
  X(MountDevPts, "mount /dev/pts")                                          \
  X(MountTmp, "mount /tmp")                                                 \
  X(ConfigureAddress, "configure container network interface")              \
  X(PivotRoot, "pivot into container root filesystem")                      \
  X(UmountOldRoot, "detach old root filesystem")                            \
  X(RemountReadonly, "remount filesystem read-only")                        \
  X(DropCapabilities, "drop Linux capabilities")                            \
  X(SwitchUser, "switch to container user")                                 \
  X(SetNoNewPrivs, "set no_new_privs")                                      \
  X(InstallSeccomp, "install seccomp filter")                               \
  X(Execve, "execute container entrypoint")                                 \
  /* --- exec / join (setns) --- */                                         \
  X(OpenNamespace, "open container namespace")                              \
  X(JoinNamespace, "join container namespace")                              \
  /* --- generic I/O --- */                                                 \
  X(OpenFile, "open file")                                                  \
  X(ReadFile, "read file")                                                  \
  X(WriteFile, "write file")                                                \
  X(CreateDirectory, "create directory")                                    \
  X(RemovePath, "remove path")                                              \
  X(Unsupported, "use unsupported kernel feature")                          \
  X(Internal, "perform internal runtime operation")

enum class Op : std::uint16_t {
#define MC_OP_ENUM(name, desc) name,
  MC_OP_LIST(MC_OP_ENUM)
#undef MC_OP_ENUM
};

// "create container process" - reads naturally after "Failed to ".
const char* op_description(Op op) noexcept;
// "CloneProcess" - stable machine-readable token for logs and tests.
const char* op_name(Op op) noexcept;

// "EPERM" for EPERM. Returns "" for 0 and for codes we do not name.
const char* errno_name(int err) noexcept;

// ---------------------------------------------------------------------------
// ChildStatus - the child's error type. POD, no allocation, no exceptions.
// Every step_* function in the post-clone sequence returns one of these.
// ---------------------------------------------------------------------------
struct ChildStatus {
  Op op = Op::None;
  int err = 0;  // errno, or 0 when the failure is not a syscall failure

  [[nodiscard]] constexpr bool ok() const noexcept { return op == Op::None; }
  [[nodiscard]] static constexpr ChildStatus success() noexcept { return {}; }
  [[nodiscard]] static constexpr ChildStatus fail(Op o, int e) noexcept {
    return ChildStatus{o, e};
  }
};

// Serialised child failure. Must stay well under PIPE_BUF (4096) so a single
// write() is atomic and can never interleave with anything else on the pipe.
struct ChildErrorWire {
  std::uint32_t magic;       // kChildErrorMagic; guards against garbage
  std::uint16_t op;          // static_cast<uint16_t>(Op)
  std::uint16_t detail_len;  // bytes used in detail[]
  std::int32_t err;          // errno
  std::int32_t reserved;
  char detail[184];  // NUL-padded; filled with memcpy, never snprintf
};
inline constexpr std::uint32_t kChildErrorMagic = 0x4D434552u;  // "MCER"
static_assert(sizeof(ChildErrorWire) == 200,
              "ChildErrorWire layout changed; it is written raw to a pipe");
static_assert(sizeof(ChildErrorWire) <= 4096,
              "ChildErrorWire must fit in PIPE_BUF for an atomic write()");
static_assert(std::is_trivially_copyable_v<ChildErrorWire>,
              "ChildErrorWire is memcpy'd across the clone boundary");

// ---------------------------------------------------------------------------
// Error - the parent's rich error type.
// ---------------------------------------------------------------------------
class Error {
 public:
  Error() = default;

  // A syscall returned -1. `detail` summarises the arguments that matter,
  // e.g. "CLONE_NEWPID|CLONE_NEWUTS" or "/proc -> /rootfs/proc, MS_NOSUID".
  static Error syscall(Op op, std::string_view name, int errnum,
                       std::string detail = {});

  // The caller gave us something we will not accept.
  static Error invalid(Op op, std::string what);

  // The kernel or a userspace library cannot do this on this host.
  static Error unsupported(Op op, std::string what);

  // Reconstruct a parent-side Error from a failure reported by the child.
  static Error from_child(const ChildErrorWire& wire);

  [[nodiscard]] Op op() const noexcept { return op_; }
  [[nodiscard]] int err() const noexcept { return err_; }
  [[nodiscard]] const std::string& syscall_name() const noexcept {
    return syscall_;
  }
  [[nodiscard]] const std::string& detail() const noexcept { return detail_; }
  [[nodiscard]] bool from_child_process() const noexcept { return from_child_; }

  // The single user-facing rendering. Examples:
  //   Failed to create container process: clone3(CLONE_NEWPID|CLONE_NEWUSER):
  //       Operation not permitted (EPERM)
  //   Failed to validate root filesystem: /rootfs has no /bin/sh
  [[nodiscard]] std::string message() const;

  // Adds context without losing the original, e.g. the container id.
  Error& with_context(std::string ctx) &;
  Error&& with_context(std::string ctx) &&;

 private:
  Op op_ = Op::Internal;
  int err_ = 0;
  bool from_child_ = false;
  std::string syscall_;
  std::string detail_;
  std::string context_;
};

// ---------------------------------------------------------------------------
// Expected<T> - the result type. Deliberately NOT std::expected:
//   * <expected> is C++23; we target C++20 so stock GCC 13 works.
//   * std::expected::value() throws, which is exactly wrong in the code paths
//     that are compiled -fno-exceptions.
// Accessing the wrong alternative here aborts with a diagnostic instead.
// ---------------------------------------------------------------------------
struct Void {};

template <class E>
class Unexpected {
 public:
  explicit Unexpected(E e) : err_(std::move(e)) {}
  E& error() & noexcept { return err_; }
  const E& error() const& noexcept { return err_; }
  E&& error() && noexcept { return std::move(err_); }

 private:
  E err_;
};
template <class E>
Unexpected(E) -> Unexpected<E>;

[[noreturn]] void expected_access_violation(const char* what,
                                            const std::string& detail) noexcept;

template <class T, class E = Error>
class [[nodiscard]] Expected {
  using Stored = std::conditional_t<std::is_void_v<T>, Void, T>;

 public:
  using value_type = T;
  using error_type = E;

  // Success with a value. Disabled when T is void.
  template <class U = Stored,
            std::enable_if_t<!std::is_void_v<T> &&
                                 std::is_constructible_v<Stored, U&&> &&
                                 !std::is_same_v<std::decay_t<U>, Expected>,
                             int> = 0>
  Expected(U&& v) : slot_(std::in_place_index<0>, std::forward<U>(v)) {}

  // Success with no value (the Expected<void> case).
  Expected() : slot_(std::in_place_index<0>, Stored{}) {}

  Expected(Unexpected<E> u)
      : slot_(std::in_place_index<1>, std::move(u).error()) {}

  [[nodiscard]] bool has_value() const noexcept { return slot_.index() == 0; }
  explicit operator bool() const noexcept { return has_value(); }

  [[nodiscard]] const E& error() const& noexcept {
    if (has_value()) {
      expected_access_violation("error", "Expected holds a value");
    }
    return std::get<1>(slot_);
  }
  [[nodiscard]] E&& error() && {
    if (has_value()) {
      expected_access_violation("error", "Expected holds a value");
    }
    return std::get<1>(std::move(slot_));
  }

  template <class U = T, std::enable_if_t<!std::is_void_v<U>, int> = 0>
  [[nodiscard]] const U& value() const& {
    check_has_value();
    return std::get<0>(slot_);
  }
  template <class U = T, std::enable_if_t<!std::is_void_v<U>, int> = 0>
  [[nodiscard]] U& value() & {
    check_has_value();
    return std::get<0>(slot_);
  }
  template <class U = T, std::enable_if_t<!std::is_void_v<U>, int> = 0>
  [[nodiscard]] U&& value() && {
    check_has_value();
    return std::get<0>(std::move(slot_));
  }

  template <class U = T, std::enable_if_t<!std::is_void_v<U>, int> = 0>
  const U& operator*() const& {
    return value();
  }
  template <class U = T, std::enable_if_t<!std::is_void_v<U>, int> = 0>
  U& operator*() & {
    return value();
  }
  template <class U = T, std::enable_if_t<!std::is_void_v<U>, int> = 0>
  const U* operator->() const {
    return &value();
  }
  template <class U = T, std::enable_if_t<!std::is_void_v<U>, int> = 0>
  U* operator->() {
    return &value();
  }

  template <class U>
  [[nodiscard]] T value_or(U&& fallback) const& {
    return has_value() ? std::get<0>(slot_)
                       : static_cast<T>(std::forward<U>(fallback));
  }

 private:
  void check_has_value() const {
    if (!has_value()) {
      expected_access_violation("value", std::get<1>(slot_).message());
    }
  }
  std::variant<Stored, E> slot_;
};

// A successful Expected<void>.
inline Expected<void> Ok() {
  return Expected<void>{};
}

// A failed Expected of any type, from an Error.
inline Unexpected<Error> Err(Error e) {
  return Unexpected<Error>(std::move(e));
}

// ---------------------------------------------------------------------------
// Propagation macros.
//
// These use GCC/Clang statement expressions. That is a deliberate, documented
// dependency: this project is Linux + GCC/Clang only, and the alternative -
// hand-writing the if/return at every call site - is exactly where real code
// hides unchecked failures.
//
// Each body is introduced with __extension__, which is how you tell GCC and
// Clang "yes, this is a language extension, and I meant it". Without it every
// translation unit that expands one of these macros emits -Wpedantic's "ISO
// C++ forbids braced-groups within expressions", which makes MC_WERROR=ON
// impossible to turn on. The alternative - dropping -Wpedantic tree-wide -
// would cost real warnings everywhere to silence one intentional extension.
// ---------------------------------------------------------------------------

// Evaluates to the value on success; returns the error from the enclosing
// function on failure. For Expected<T> where T is not void.
#define MC_TRY(expr)                              \
  __extension__({                                 \
    auto _mc_r = (expr);                          \
    if (!_mc_r)                                   \
      return ::mc::Err(std::move(_mc_r).error()); \
    std::move(_mc_r).value();                     \
  })

// Propagates failure of an Expected<void>. Use as a statement.
#define MC_CHECK(expr)                            \
  do {                                            \
    auto _mc_r = (expr);                          \
    if (!_mc_r)                                   \
      return ::mc::Err(std::move(_mc_r).error()); \
  } while (0)

// Wraps a syscall that signals failure with a negative return value.
// Evaluates to the syscall's return value on success.
#define MC_SYS(op, name, call, detail)                                       \
  __extension__({                                                            \
    auto _mc_rc = (call);                                                    \
    if (_mc_rc < 0) {                                                        \
      return ::mc::Err(::mc::Error::syscall((op), (name), errno, (detail))); \
    }                                                                        \
    _mc_rc;                                                                  \
  })

// Child-side equivalent: no allocation, returns a ChildStatus.
#define MC_CHILD_SYS(op, call)                     \
  do {                                             \
    if ((call) < 0)                                \
      return ::mc::ChildStatus::fail((op), errno); \
  } while (0)

// ---------------------------------------------------------------------------
// ScopeGuard / Rollback - initialisation as a transaction.
//
// Container setup acquires a chain of privileged resources (cgroup, veth,
// mounts, netns). If step N fails, steps N-1..0 must be undone in reverse or
// the host is left with orphaned cgroups and dangling veth interfaces.
//
// NOTE: cleanup actions must capture only COPYABLE state (paths, ints, names),
// because std::function requires a copyable callable. Capture a raw int fd,
// never a UniqueFd.
// ---------------------------------------------------------------------------
class ScopeGuard {
 public:
  explicit ScopeGuard(std::function<void()> fn) : fn_(std::move(fn)) {}
  ScopeGuard(ScopeGuard&& other) noexcept : fn_(std::move(other.fn_)) {
    other.fn_ = nullptr;
  }
  ScopeGuard& operator=(ScopeGuard&&) = delete;
  ScopeGuard(const ScopeGuard&) = delete;
  ScopeGuard& operator=(const ScopeGuard&) = delete;
  ~ScopeGuard() {
    if (fn_)
      fn_();
  }

  void dismiss() noexcept { fn_ = nullptr; }

 private:
  std::function<void()> fn_;
};

// An ordered ledger of undo actions. Push in acquisition order; run() unwinds
// in reverse. Lives in the PARENT only - the child's resources are torn down by
// the kernel when its namespaces die.
class Rollback {
 public:
  Rollback() = default;
  Rollback(const Rollback&) = delete;
  Rollback& operator=(const Rollback&) = delete;
  ~Rollback() { run(); }

  // `what` names the resource, for the debug log line if the undo itself fails.
  void push(std::string what, std::function<void()> undo);

  // Unwind everything not yet dismissed, most-recent-first. Never throws; a
  // failing undo action is logged and the remaining actions still run.
  void run() noexcept;

  // Commit: the resources are now owned by the caller, do not unwind them.
  void dismiss() noexcept { actions_.clear(); }

  [[nodiscard]] std::size_t size() const noexcept { return actions_.size(); }

 private:
  struct Action {
    std::string what;
    std::function<void()> undo;
  };
  std::vector<Action> actions_;
};

}  // namespace mc
