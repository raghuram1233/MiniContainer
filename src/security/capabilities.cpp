// SPDX-License-Identifier: MIT
//
// MiniContainer - Tier 2: capability resolution (parent) and dropping (child).
//
// WHY A STATIC TABLE INSTEAD OF libcap's cap_from_name()
// ------------------------------------------------------
// cap_from_name()/cap_to_name() allocate, depend on the libcap version the
// host happens to ship, and cap_to_name() returns heap memory the caller must
// free. Capability numbers are frozen kernel ABI - CAP_CHOWN has been 0 since
// 1999 and can never be renumbered - so a table costs nothing to keep correct
// and gives us three properties libcap cannot: name resolution that is a pure
// function (unit-testable with no root, no /proc, no host libcap), a stable
// canonical spelling for error messages, and a known highest capability number
// so the bounding-set loop below has a definite upper bound even on a kernel
// newer than the headers this was compiled against.
//
// WHY THE CHILD SIDE USES capset(2) AND NOT cap_set_proc()
// --------------------------------------------------------
// step_drop_capabilities runs between clone() and execve(), where a single
// malloc can deadlock forever (see errors.h). libcap's cap_set_proc() takes a
// cap_t, which is a heap object. capset(2) takes two 32-bit words on the
// stack, so the whole child path here is allocation-free.
//
// WHY THE BOUNDING SET IS CLEARED FIRST
// -------------------------------------
// PR_CAPBSET_DROP itself requires CAP_SETPCAP in the *effective* set. Shrink
// the permitted/effective sets first and the bounding set is frozen with
// CAP_SYS_ADMIN still in it, which means a setuid-root binary inside the
// container regains it across execve - the exact hole dropping capabilities is
// supposed to close. Bounding first, capset second.

#include <linux/capability.h>
#include <sys/prctl.h>
#include <sys/syscall.h>

#include <unistd.h>

#include <cstdint>
#include <string>
#include <string_view>

#include "minicontainer/container.h"
#include "minicontainer/errors.h"
#include "minicontainer/security.h"

namespace mc {

namespace {

// The kernel's capability numbering, frozen ABI. The index into this table is
// the capability number, so kCapabilityNames[CAP_SYS_ADMIN] is "CAP_SYS_ADMIN".
constexpr const char* kCapabilityNames[] = {
    "CAP_CHOWN",             // 0
    "CAP_DAC_OVERRIDE",      // 1
    "CAP_DAC_READ_SEARCH",   // 2
    "CAP_FOWNER",            // 3
    "CAP_FSETID",            // 4
    "CAP_KILL",              // 5
    "CAP_SETGID",            // 6
    "CAP_SETUID",            // 7
    "CAP_SETPCAP",           // 8
    "CAP_LINUX_IMMUTABLE",   // 9
    "CAP_NET_BIND_SERVICE",  // 10
    "CAP_NET_BROADCAST",     // 11
    "CAP_NET_ADMIN",         // 12
    "CAP_NET_RAW",           // 13
    "CAP_IPC_LOCK",          // 14
    "CAP_IPC_OWNER",         // 15
    "CAP_SYS_MODULE",        // 16
    "CAP_SYS_RAWIO",         // 17
    "CAP_SYS_CHROOT",        // 18
    "CAP_SYS_PTRACE",        // 19
    "CAP_SYS_PACCT",         // 20
    "CAP_SYS_ADMIN",         // 21
    "CAP_SYS_BOOT",          // 22
    "CAP_SYS_NICE",          // 23
    "CAP_SYS_RESOURCE",      // 24
    "CAP_SYS_TIME",          // 25
    "CAP_SYS_TTY_CONFIG",    // 26
    "CAP_MKNOD",             // 27
    "CAP_LEASE",             // 28
    "CAP_AUDIT_WRITE",       // 29
    "CAP_AUDIT_CONTROL",     // 30
    "CAP_SETFCAP",           // 31
    "CAP_MAC_OVERRIDE",      // 32
    "CAP_MAC_ADMIN",         // 33
    "CAP_SYSLOG",            // 34
    "CAP_WAKE_ALARM",        // 35
    "CAP_BLOCK_SUSPEND",     // 36
    "CAP_AUDIT_READ",        // 37
    "CAP_PERFMON",           // 38
    "CAP_BPF",               // 39
    "CAP_CHECKPOINT_RESTORE",
};

constexpr int kCapabilityCount =
    static_cast<int>(sizeof(kCapabilityNames) / sizeof(kCapabilityNames[0]));

// Spot-check the table against the kernel headers we compiled with. A shifted
// table would silently keep the wrong capabilities, which is the worst kind of
// bug this file could have.
static_assert(CAP_CHOWN == 0,
              "capability table is out of step with the kernel");
static_assert(CAP_NET_BIND_SERVICE == 10, "capability table is misaligned");
static_assert(CAP_SYS_ADMIN == 21, "capability table is misaligned");
static_assert(CAP_SETFCAP == 31, "capability table is misaligned");
static_assert(kCapabilityCount <= 64,
              "cap masks are uint64_t; a 65th capability needs a wider type");

constexpr std::uint64_t cap_bit(int cap) noexcept {
  return std::uint64_t{1} << cap;
}

// Every capability this build knows about. Used for "ALL" and for privileged
// containers. Capabilities a newer kernel adds are simply not in it; that errs
// towards dropping, which is the safe direction.
constexpr std::uint64_t kAllCapabilities =
    (kCapabilityCount == 64) ? ~std::uint64_t{0}
                             : (cap_bit(kCapabilityCount) - 1);

constexpr char ascii_upper(char c) noexcept {
  return (c >= 'a' && c <= 'z') ? static_cast<char>(c - 'a' + 'A') : c;
}

bool equals_ignore_case(std::string_view a, std::string_view b) noexcept {
  if (a.size() != b.size()) {
    return false;
  }
  for (std::size_t i = 0; i < a.size(); ++i) {
    if (ascii_upper(a[i]) != ascii_upper(b[i])) {
      return false;
    }
  }
  return true;
}

// "CAP_NET_RAW" and "net_raw" both reduce to "NET_RAW" for lookup.
std::string_view strip_cap_prefix(std::string_view name) noexcept {
  if (name.size() > 4 && equals_ignore_case(name.substr(0, 4), "CAP_")) {
    return name.substr(4);
  }
  return name;
}

bool is_all_keyword(std::string_view name) noexcept {
  return equals_ignore_case(strip_cap_prefix(name), "ALL");
}

}  // namespace

// ---------------------------------------------------------------------------
// Parent side: name resolution and mask arithmetic. Pure functions - no
// syscalls, no /proc, no allocation beyond the error string.
// ---------------------------------------------------------------------------

Expected<int> capability_from_name(const std::string& name) {
  const std::string_view bare = strip_cap_prefix(name);
  if (!bare.empty()) {
    for (int cap = 0; cap < kCapabilityCount; ++cap) {
      if (equals_ignore_case(bare, strip_cap_prefix(kCapabilityNames[cap]))) {
        return cap;
      }
    }
  }
  // Deliberately an error and not a silently-ignored entry: a typo in
  // --cap-add must never produce a container with fewer privileges than the
  // user asked for, and a typo in --cap-drop must never produce one with more.
  return Err(Error::invalid(Op::ValidateConfig,
                            "unknown capability \"" + name + "\""));
}

const char* capability_name(int cap) noexcept {
  if (cap < 0 || cap >= kCapabilityCount) {
    return "";  // same convention as errno_name(): "" rather than nullptr
  }
  return kCapabilityNames[cap];
}

std::uint64_t default_capability_mask() noexcept {
  // Docker's default set, which is the de-facto standard for "enough to run
  // ordinary software". Everything omitted here grants host-level power:
  // SYS_ADMIN (mount, and a hundred other things), SYS_MODULE (load kernel
  // code), SYS_TIME (skew the host clock), SYS_BOOT (reboot the host),
  // SYS_RAWIO (talk to devices directly), SYS_PTRACE (inspect host processes
  // that share the pid namespace), NET_ADMIN (reconfigure host networking when
  // --network=host), and MAC_ADMIN/MAC_OVERRIDE (disarm LSM policy).
  return cap_bit(CAP_CHOWN) | cap_bit(CAP_DAC_OVERRIDE) | cap_bit(CAP_FSETID) |
         cap_bit(CAP_FOWNER) | cap_bit(CAP_MKNOD) | cap_bit(CAP_NET_RAW) |
         cap_bit(CAP_SETGID) | cap_bit(CAP_SETUID) | cap_bit(CAP_SETFCAP) |
         cap_bit(CAP_SETPCAP) | cap_bit(CAP_NET_BIND_SERVICE) |
         cap_bit(CAP_SYS_CHROOT) | cap_bit(CAP_KILL) | cap_bit(CAP_AUDIT_WRITE);
}

Expected<std::uint64_t> resolve_capability_mask(const SecurityConfig& sec) {
  // --privileged is the documented escape hatch: it keeps everything, so the
  // cap_add/cap_drop lists are irrelevant rather than contradictory.
  if (sec.privileged) {
    return kAllCapabilities;
  }

  std::uint64_t mask = default_capability_mask();

  // Drop first, then add - the order SecurityConfig documents. It only matters
  // when a capability appears in both lists, and then "add wins" is the
  // reading that cannot surprise: the user's most specific request is honoured.
  for (const std::string& name : sec.cap_drop) {
    if (is_all_keyword(name)) {
      mask = 0;
      continue;
    }
    mask &= ~cap_bit(MC_TRY(capability_from_name(name)));
  }
  for (const std::string& name : sec.cap_add) {
    if (is_all_keyword(name)) {
      mask = kAllCapabilities;
      continue;
    }
    mask |= cap_bit(MC_TRY(capability_from_name(name)));
  }
  return mask;
}

// ---------------------------------------------------------------------------
// Child side: post-clone, pre-execve. No allocation, no locks, no throwing.
// ---------------------------------------------------------------------------

ChildStatus step_drop_capabilities(const ChildContext& ctx) noexcept {
  if (!ctx.drop_capabilities) {
    return ChildStatus::success();
  }
  const std::uint64_t keep = ctx.cap_keep_mask;

  // 1. The bounding set, while CAP_SETPCAP is still effective. PR_CAPBSET_READ
  //    first so that a capability the kernel does not know (EINVAL) or that is
  //    already gone - the common case when we were started by a runtime that
  //    had itself dropped capabilities - is skipped instead of being reported
  //    as a failure. A drop that we genuinely need and that genuinely fails is
  //    still fatal: silently leaving CAP_SYS_ADMIN in the bounding set would
  //    hand it back to any setuid-root binary the container execs.
  for (int cap = 0; cap < kCapabilityCount; ++cap) {
    if ((keep & cap_bit(cap)) != 0) {
      continue;
    }
    if (::prctl(PR_CAPBSET_READ, cap, 0, 0, 0) <= 0) {
      continue;
    }
    MC_CHILD_SYS(Op::DropCapabilities, ::prctl(PR_CAPBSET_DROP, cap, 0, 0, 0));
  }

  // 2. The permitted, effective and inheritable sets, via raw capset(2).
  //    Version 3 is the 64-bit format: two 32-bit words per set.
  struct ::__user_cap_header_struct header {};
  header.version = _LINUX_CAPABILITY_VERSION_3;
  header.pid = 0;  // 0 means "this thread"

  struct ::__user_cap_data_struct data[2]{};
  MC_CHILD_SYS(Op::DropCapabilities, ::syscall(SYS_capget, &header, data));

  // Mask the CURRENT sets rather than assigning the keep mask outright. capset
  // rejects any request that would *raise* a set (EPERM), so assigning
  // cap_keep_mask directly would fail whenever we hold less than the user
  // asked to keep - inside a user namespace, say, or under an outer runtime
  // that already dropped something. Intersecting still satisfies the contract
  // (nothing outside the mask survives) and can only ever keep fewer
  // capabilities, never more.
  const std::uint32_t low = static_cast<std::uint32_t>(keep);
  const std::uint32_t high = static_cast<std::uint32_t>(keep >> 32);
  data[0].effective &= low;
  data[0].permitted &= low;
  data[0].inheritable &= low;
  data[1].effective &= high;
  data[1].permitted &= high;
  data[1].inheritable &= high;

  // The ambient set needs no explicit handling: the kernel clears an ambient
  // capability the moment it leaves either permitted or inheritable, which the
  // capset below does for every capability outside the mask.
  MC_CHILD_SYS(Op::DropCapabilities, ::syscall(SYS_capset, &header, data));
  return ChildStatus::success();
}

ChildStatus step_switch_user(const ChildContext& ctx) noexcept {
  if (!ctx.switch_user) {
    return ChildStatus::success();
  }

  // Raw syscalls, not glibc's setgid()/setuid(): the glibc wrappers implement
  // POSIX's "all threads change identity together" by broadcasting a signal to
  // every thread through nptl's setxid machinery, which takes a lock. Post
  // clone() we are single-threaded by construction, so the per-thread syscall
  // is both correct and the only allocation-free option.

  // setgroups BEFORE setgid/setuid: dropping supplementary groups needs
  // CAP_SETGID, which is gone the instant we become a non-root uid. Without
  // this the container user keeps every supplementary group of the runtime -
  // typically root's - and a file group-readable by, say, `docker` or `disk`
  // stays reachable.
  //
  // EPERM here means a user namespace whose /proc/<pid>/setgroups the parent
  // wrote "deny" to (process.h explains why it must). In that namespace the
  // inherited groups are unmapped to the overflow gid and grant nothing, and
  // the call can never succeed, so it is not a failure. Every other errno is.
  // Outside a user namespace, a genuine lack of CAP_SETGID is still caught:
  // the setgid below fails with the same EPERM and is reported.
  if (::syscall(SYS_setgroups, 0, nullptr) < 0 && errno != EPERM) {
    return ChildStatus::fail(Op::SwitchUser, errno);
  }

  // setgid BEFORE setuid. Reversed, the setuid succeeds, CAP_SETGID is gone
  // with it, and the setgid then fails - leaving a process that looks
  // unprivileged but is still in group 0. That failure is loud here; the
  // dangerous version is the one where nobody checks the return value.
  MC_CHILD_SYS(Op::SwitchUser, ::syscall(SYS_setgid, ctx.gid));
  MC_CHILD_SYS(Op::SwitchUser, ::syscall(SYS_setuid, ctx.uid));
  return ChildStatus::success();
}

}  // namespace mc
