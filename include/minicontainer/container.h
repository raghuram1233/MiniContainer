// SPDX-License-Identifier: MIT
//
// MiniContainer - Tier 2: the child setup contract.
//
// THE CENTRAL CONSTRAINT
// ----------------------
// Everything in this header describes code that runs BETWEEN clone() and
// execve(). In that window the process may hold a malloc lock inherited from a
// thread that does not exist in this address space, so a single allocation can
// deadlock forever. Every child-side function declared here therefore:
//
//   * returns ChildStatus (a POD), never Expected<T> (which owns a std::string)
//   * takes preformatted, fixed-size data, never std::string or std::vector
//   * never throws, never locks, never calls a libc function that allocates
//
// That is why ChildContext exists. The PARENT builds it completely before
// clone(), packing every string the child will need into a fixed arena, and the
// child only ever reads it. Pointers into the arena stay valid in the child
// because clone() without CLONE_VM gives the child a copy-on-write address
// space at the SAME virtual addresses.
//
// STEP ORDER IS THE Op ENUM
// -------------------------
// errors.h's MC_OP_LIST documents the child-setup ops "in execution order" and
// is the authority for this table. Note that every mount happens BEFORE
// PivotRoot: we mount into <rootfs>/proc, <rootfs>/sys, ... while the old root
// is still reachable, then pivot once. That is what runc does, and it avoids
// needing a working /proc in order to mount /proc.
#pragma once

#include <sys/types.h>

#include <cstddef>
#include <cstdint>
#include <string>

#include "minicontainer/config.h"
#include "minicontainer/errors.h"
#include "minicontainer/process.h"

namespace mc {

// ---------------------------------------------------------------------------
// Fixed capacities. Exceeding any of them is a parent-side validation error
// (Op::ValidateConfig), never a child-side truncation - silently dropping an
// argv entry or a bind mount would be far worse than refusing the container.
// ---------------------------------------------------------------------------
inline constexpr std::size_t kArenaSize = 64 * 1024;
inline constexpr std::size_t kMaxArgs = 64;
inline constexpr std::size_t kMaxEnv = 128;
inline constexpr std::size_t kMaxBindMounts = 32;
inline constexpr std::size_t kMaxSeccompInsns = 2048;

// One bind mount, already split and resolved by the parent.
struct BindMountSpec {
  const char* source = nullptr;  // host path, points into ChildContext::arena
  const char* target = nullptr;  // absolute path INSIDE the container
  bool read_only = false;
};

// A device node to mknod under <rootfs>/dev.
struct DeviceNodeSpec {
  const char* name;  // "null", "zero", ... (a string literal, not arena)
  unsigned major;
  unsigned minor;
  unsigned mode;  // permission bits; S_IFCHR is added by the mknod call
};

// The classic minimal set. /dev/tty is included because a shell without it
// cannot open its controlling terminal and many programs special-case it.
const DeviceNodeSpec* default_device_nodes(std::size_t& count) noexcept;

// ---------------------------------------------------------------------------
// ChildContext - everything the child needs, built entirely by the parent.
//
// Large (~64KB) and heap-allocated by the parent before clone(). Deliberately
// trivially copyable, with no owning types anywhere inside it.
// ---------------------------------------------------------------------------
struct ChildContext {
  // --- synchronisation fds (see process.h's handshake diagram) ---
  int sync_fd = -1;   // child reads one byte; 'G' means "maps are written"
  int error_fd = -1;  // child writes a ChildErrorWire here on failure
  int log_fd = -1;    // async-signal-safe child log sink; -1 disables

  // Where the entrypoint's stdout and stderr go. -1 means "inherit the
  // parent's", which is what an attached `run` wants - the user is watching a
  // terminal. A detached container has no terminal to inherit, so the parent
  // opens a capture file and puts its fd here, which is what makes `logs`
  // possible at all.
  int stdout_fd = -1;
  int stderr_fd = -1;

  // --- identity ---
  const char* rootfs = nullptr;       // canonical, absolute
  const char* hostname = nullptr;     // nullptr when there is no UTS namespace
  const char* working_dir = nullptr;  // chdir target inside the container

  // --- execve payload, NULL-terminated, pointing into arena ---
  char* argv[kMaxArgs + 1] = {};
  char* envp[kMaxEnv + 1] = {};

  // --- filesystem ---
  BindMountSpec binds[kMaxBindMounts] = {};
  std::size_t bind_count = 0;
  bool readonly_rootfs = false;
  bool mount_sys = true;
  bool mount_devpts = true;

  // --- networking (applied inside the new netns, before pivot_root) ---
  const char* container_ip_cidr = nullptr;  // "10.88.0.2/16"; nullptr = skip
  const char* gateway_ip = nullptr;
  const char* veth_name = nullptr;  // interface name inside the container
  bool configure_loopback = true;

  // --- security ---
  // Capability sets are computed by the PARENT from cap_add/cap_drop, because
  // resolving names to bits allocates. The child only applies the bitmask.
  std::uint64_t cap_keep_mask = 0;
  bool drop_capabilities = false;
  bool no_new_privs = true;
  bool switch_user = false;
  ::uid_t uid = 0;
  ::gid_t gid = 0;

  // Seccomp is exported to raw BPF by the parent (libseccomp allocates); the
  // child installs it with a bare seccomp(2) call.
  bool install_seccomp = false;
  std::size_t seccomp_insn_count = 0;
  // A sock_filter is {u16 code; u8 jt; u8 jf; u32 k} = 8 bytes. Storing it as
  // a byte array keeps <linux/filter.h> out of this header.
  unsigned char seccomp_insns[kMaxSeccompInsns * 8] = {};

  // --- string storage backing every const char* above ---
  std::size_t arena_used = 0;
  char arena[kArenaSize] = {};
};

// ---------------------------------------------------------------------------
// Parent-side builder. Validates every capacity above and packs the arena.
// This is ordinary parent code: it allocates freely.
// ---------------------------------------------------------------------------
Expected<void> build_child_context(const ContainerConfig& config,
                                   ChildContext& out);

// Copies `text` into the arena and returns a stable pointer, or nullptr when
// the arena is exhausted. Exposed so each module can add its own strings.
char* arena_put(ChildContext& ctx, const char* text) noexcept;

// The clone flags a config implies: CLONE_NEWPID|NEWNS|NEWUTS|NEWIPC always,
// plus NEWNET unless NetworkMode::Host, plus NEWUSER when userns is on.
std::uint64_t clone_flags_for(const ContainerConfig& config) noexcept;

// ---------------------------------------------------------------------------
// The step table.
//
// Each step is a plain function pointer, so the table is a constant array -
// no std::function, no vtable, nothing that allocates. A step returns
// ChildStatus::success(), or fails with the Op that names it. A step that does
// not apply to this config returns success immediately.
// ---------------------------------------------------------------------------
using ChildStepFn = ChildStatus (*)(const ChildContext&);

struct ChildStep {
  Op op;
  ChildStepFn fn;
  const char* name;  // matches op_name(op); duplicated for child-side logging
};

// The table, in Op-enum execution order. `count` receives its length.
const ChildStep* child_step_table(std::size_t& count) noexcept;

// Runs the whole table in order, stopping at the first failure.
ChildStatus run_child_steps(const ChildContext& ctx) noexcept;

// The clone3 child entry point, matching process.h's ChildFn signature. Blocks
// on sync_fd, runs the step table, reports any failure down error_fd, then
// execve()s. Only returns (via _exit) on failure.
int container_child_main(void* arg) noexcept;

// Reports a child-side failure to the parent over error_fd. async-signal-safe:
// builds a ChildErrorWire on the stack and does a single write(2).
void report_child_error(int error_fd, ChildStatus status,
                        const char* detail) noexcept;

// ---------------------------------------------------------------------------
// Parent-side launch. Ties together process.h's clone handshake, the cgroup
// and network modules, and the step table above.
// ---------------------------------------------------------------------------
struct LaunchResult {
  ::pid_t pid = -1;
  Fd pidfd;
  std::string cgroup_path;  // empty when no cgroup was created
  std::string veth_host;    // host-side veth name, empty when not bridged
};

// Creates the container process: builds the ChildContext, creates the cgroup,
// clones, writes uid_map/gid_map, sets up host-side networking, then releases
// the child with 'G'. On any failure every resource created here is rolled
// back before returning, so a failed launch leaves no cgroup or veth behind.
Expected<LaunchResult> launch_container(const ContainerConfig& config,
                                        const RuntimePaths& paths);

}  // namespace mc
