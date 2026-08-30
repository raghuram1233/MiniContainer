// SPDX-License-Identifier: MIT
//
// MiniContainer - Tier 2: capabilities, no_new_privs, seccomp.
//
// THE SPLIT THAT MATTERS
// ----------------------
// Resolving capability NAMES to bits, and compiling a seccomp profile to BPF,
// both allocate - libcap and libseccomp are ordinary allocating libraries. So
// all of that happens PARENT-side, before clone(), and the results are stored
// in ChildContext as a bitmask and a raw BPF instruction array. The child then
// applies them with bare syscalls that cannot allocate.
//
// ORDER IS NOT NEGOTIABLE
// -----------------------
//   1. no_new_privs BEFORE seccomp. seccomp(SECCOMP_SET_MODE_FILTER) without
//      CAP_SYS_ADMIN requires no_new_privs, else it returns EACCES. Since we
//      are about to drop CAP_SYS_ADMIN, no_new_privs must come first.
//   2. Capabilities dropped AFTER every step that needs them - mounting,
//      mknod and sethostname all require capabilities the container itself
//      must not keep - and before execve.
//   3. setgroups, then setgid, then setuid. Once uid is non-zero you can no
//      longer change gid, so a setuid-first sequence silently leaves the
//      process in the root group: a classic privilege-retention bug.
#pragma once

#include <sys/types.h>

#include <cstdint>
#include <string>

#include "minicontainer/config.h"
#include "minicontainer/container.h"
#include "minicontainer/errors.h"

namespace mc {

// ---------------------------------------------------------------------------
// Parent side.
// ---------------------------------------------------------------------------

// "CAP_NET_BIND_SERVICE" or "NET_BIND_SERVICE" -> the capability bit.
// Case-insensitive, CAP_ prefix optional. Returns an error for unknown names
// rather than silently ignoring them: a typo in --cap-add must not quietly
// produce a container with fewer privileges than the user asked for.
Expected<int> capability_from_name(const std::string& name);
const char* capability_name(int cap) noexcept;

// The default set a container keeps: enough to run ordinary software, minus
// everything granting host-level power (SYS_ADMIN, SYS_MODULE, SYS_TIME,
// SYS_BOOT, SYS_RAWIO, MAC_ADMIN/OVERRIDE, and friends).
std::uint64_t default_capability_mask() noexcept;

// Applies cap_drop then cap_add on top of the default set, honouring "ALL" in
// either list, and returns the mask the child should keep. SecurityConfig
// documents that order; it matters when both lists name the same capability.
Expected<std::uint64_t> resolve_capability_mask(const SecurityConfig& sec);

// Compiles a seccomp profile to raw BPF and stores it in ctx. A no-op for
// SeccompMode::Off. When the build has no libseccomp this returns an
// Op::Unsupported error rather than silently running the container unfiltered.
Expected<void> build_seccomp_program(const SecurityConfig& sec,
                                     ChildContext& ctx);

// True when this build linked libseccomp (MC_ENABLE_SECCOMP).
bool seccomp_available() noexcept;

// ---------------------------------------------------------------------------
// Child side. No allocation.
// ---------------------------------------------------------------------------

// prctl(PR_SET_NO_NEW_PRIVS, 1). Must run before seccomp installation.
ChildStatus step_set_no_new_privs(const ChildContext& ctx) noexcept;

// Drops every capability outside ctx.cap_keep_mask from the permitted,
// effective and inheritable sets, and clears the bounding set so they cannot
// be regained across execve by a setuid binary.
ChildStatus step_drop_capabilities(const ChildContext& ctx) noexcept;

// setgroups({}), setgid, then setuid - in that order.
ChildStatus step_switch_user(const ChildContext& ctx) noexcept;

// seccomp(SECCOMP_SET_MODE_FILTER) with the parent-built program.
ChildStatus step_install_seccomp(const ChildContext& ctx) noexcept;

}  // namespace mc
