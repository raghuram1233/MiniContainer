// SPDX-License-Identifier: MIT
//
// Unit tests for the parent side of src/security/: capability name
// resolution, the default capability set, cap_add/cap_drop mask arithmetic,
// and seccomp program construction.
//
// Everything exercised here is a PURE function of its arguments. Nothing in
// this file changes process credentials, calls prctl/capset, or installs a
// filter on the running test process - the child-side steps
// (step_drop_capabilities, step_switch_user, step_install_seccomp) genuinely
// need root and a fresh namespace and therefore live in the integration
// suite. build_seccomp_program is the one function here that touches
// libseccomp, and it only compiles a program into memory: seccomp_init() and
// seccomp_export_bpf() need no privileges, and the resulting BPF is written
// into a ChildContext, never loaded into the kernel.

#include <linux/capability.h>

#include <unistd.h>

#include <cstdint>
#include <cstring>
#include <memory>
#include <string>
#include <vector>

#include "minicontainer/config.h"
#include "minicontainer/container.h"
#include "minicontainer/errors.h"
#include "minicontainer/security.h"

#include <gtest/gtest.h>

using mc::capability_from_name;
using mc::capability_name;

namespace {

constexpr std::uint64_t bit(int cap) {
  return std::uint64_t{1} << cap;
}

// The capability table's length is a private detail of capabilities.cpp, but
// capability_name() returns "" outside it (the same convention errno_name()
// uses), so the count is observable without exporting it.
int known_capability_count() {
  int count = 0;
  while (capability_name(count)[0] != '\0') {
    ++count;
  }
  return count;
}

mc::SecurityConfig sec_with(std::vector<std::string> drop,
                            std::vector<std::string> add) {
  mc::SecurityConfig sec;
  sec.cap_drop = std::move(drop);
  sec.cap_add = std::move(add);
  return sec;
}

// A scratch file for --seccomp <PATH> tests: mkstemp'd so parallel test
// binaries never collide, unlinked unconditionally in the destructor.
class TempFile {
 public:
  explicit TempFile(const std::string& content) {
    char tmpl[] = "/tmp/mc-test-seccomp-XXXXXX";
    const int fd = ::mkstemp(tmpl);
    path_ = tmpl;
    if (fd >= 0) {
      (void)::write(fd, content.data(), content.size());
      ::close(fd);
    }
  }
  ~TempFile() { ::unlink(path_.c_str()); }
  TempFile(const TempFile&) = delete;
  TempFile& operator=(const TempFile&) = delete;

  const std::string& path() const { return path_; }

 private:
  std::string path_;
};

}  // namespace

// ---------------------------------------------------------------------------
// capability_from_name: spelling is normalised, typos are errors.
// ---------------------------------------------------------------------------
TEST(CapabilityNameTest, AcceptsEverySpellingOfTheSameCapability) {
  const mc::Expected<int> prefixed =
      capability_from_name("CAP_NET_BIND_SERVICE");
  const mc::Expected<int> lower = capability_from_name("net_bind_service");
  const mc::Expected<int> bare = capability_from_name("NET_BIND_SERVICE");
  const mc::Expected<int> mixed = capability_from_name("Cap_Net_Bind_Service");

  ASSERT_TRUE(prefixed.has_value());
  ASSERT_TRUE(lower.has_value());
  ASSERT_TRUE(bare.has_value());
  ASSERT_TRUE(mixed.has_value());

  // All four must land on the same kernel bit. CAP_NET_BIND_SERVICE is frozen
  // ABI at 10, so this can be pinned to the literal the kernel header gives.
  EXPECT_EQ(*prefixed, CAP_NET_BIND_SERVICE);
  EXPECT_EQ(*lower, *prefixed);
  EXPECT_EQ(*bare, *prefixed);
  EXPECT_EQ(*mixed, *prefixed);
}

TEST(CapabilityNameTest, UnknownNameIsAnErrorNotASilentSkip) {
  // The whole point: a typo in --cap-add must not be dropped on the floor. If
  // it were, the user would get a container with privileges that differ from
  // the ones they asked for and nothing would say so.
  const mc::Expected<int> typo = capability_from_name("CAP_NET_BIND_SERVIC");
  ASSERT_FALSE(typo.has_value());
  EXPECT_EQ(typo.error().op(), mc::Op::ValidateConfig);
  // The rejected spelling must appear in the message, or the user cannot tell
  // which of several --cap-add entries was wrong.
  EXPECT_NE(typo.error().message().find("CAP_NET_BIND_SERVIC"),
            std::string::npos);

  EXPECT_FALSE(capability_from_name("").has_value());
  EXPECT_FALSE(capability_from_name("CAP_").has_value());
  EXPECT_FALSE(capability_from_name("NOT_A_CAPABILITY").has_value());
  // "ALL" is a keyword handled by resolve_capability_mask, not a capability;
  // resolving it to a bit here would be wrong.
  EXPECT_FALSE(capability_from_name("ALL").has_value());
  // Stripping the prefix must happen at most once.
  EXPECT_FALSE(capability_from_name("CAP_CAP_CHOWN").has_value());
}

TEST(CapabilityNameTest, RoundTripsWithCapabilityName) {
  const int count = known_capability_count();
  ASSERT_GT(count, CAP_SYS_ADMIN);
  ASSERT_LE(count, 64) << "cap masks are uint64_t";

  for (int cap = 0; cap < count; ++cap) {
    const char* name = capability_name(cap);
    ASSERT_NE(name, nullptr);
    ASSERT_STRNE(name, "");
    const mc::Expected<int> back = capability_from_name(name);
    ASSERT_TRUE(back.has_value()) << "canonical name did not resolve: " << name;
    EXPECT_EQ(*back, cap) << "round-trip broke for " << name;
  }
}

TEST(CapabilityNameTest, OutOfRangeReturnsEmptyStringNotNullptr) {
  // Same convention as errno_name(): "" so callers can concatenate it into a
  // message without a null check.
  EXPECT_STREQ(capability_name(-1), "");
  EXPECT_STREQ(capability_name(known_capability_count()), "");
  EXPECT_STREQ(capability_name(1000), "");
}

TEST(CapabilityNameTest, TableIsAlignedWithTheKernelHeaders) {
  // A shifted table would keep the wrong capabilities while every test that
  // only checked round-tripping still passed, so anchor a few frozen numbers
  // against <linux/capability.h> itself.
  EXPECT_STREQ(capability_name(CAP_CHOWN), "CAP_CHOWN");
  EXPECT_STREQ(capability_name(CAP_NET_BIND_SERVICE), "CAP_NET_BIND_SERVICE");
  EXPECT_STREQ(capability_name(CAP_SYS_ADMIN), "CAP_SYS_ADMIN");
  EXPECT_STREQ(capability_name(CAP_SETFCAP), "CAP_SETFCAP");
}

// ---------------------------------------------------------------------------
// default_capability_mask
// ---------------------------------------------------------------------------
TEST(CapabilityMaskTest, DefaultSetExcludesHostLevelCapabilities) {
  const std::uint64_t mask = mc::default_capability_mask();

  // CAP_SYS_ADMIN is the one that matters most. It is not "one more
  // capability": it carries mount(2), pivot_root, setns, and roughly a
  // hundred other operations, so a container holding it can remount the host
  // filesystem, enter another namespace, or install a permissive seccomp
  // filter over the one we just built. Granting it by default would make
  // every other line of this runtime's isolation decorative.
  EXPECT_EQ(mask & bit(CAP_SYS_ADMIN), 0u) << "CAP_SYS_ADMIN in default set";

  EXPECT_EQ(mask & bit(CAP_SYS_MODULE), 0u)  // loads code into the host kernel
      << "CAP_SYS_MODULE in default set";
  EXPECT_EQ(mask & bit(CAP_SYS_BOOT), 0u)  // reboots the host
      << "CAP_SYS_BOOT in default set";
  EXPECT_EQ(mask & bit(CAP_SYS_TIME), 0u)  // skews the host clock
      << "CAP_SYS_TIME in default set";
}

TEST(CapabilityMaskTest, DefaultSetIncludesOrdinarySoftwareCapabilities) {
  const std::uint64_t mask = mc::default_capability_mask();

  // CAP_CHOWN: package managers and installers chown files inside the rootfs;
  // without it a great deal of ordinary software fails for no security gain,
  // since the rootfs is the container's own.
  EXPECT_NE(mask & bit(CAP_CHOWN), 0u);
  // CAP_NET_BIND_SERVICE: binding :80 inside the container is the single most
  // common reason to run one at all.
  EXPECT_NE(mask & bit(CAP_NET_BIND_SERVICE), 0u);
}

TEST(CapabilityMaskTest, DefaultSetIsNeitherEmptyNorEverything) {
  const std::uint64_t mask = mc::default_capability_mask();
  const int count = known_capability_count();
  const std::uint64_t all =
      (count == 64) ? ~std::uint64_t{0} : (bit(count) - 1);

  EXPECT_NE(mask, 0u);
  EXPECT_NE(mask, all);
  // No bit outside the table this build knows about.
  EXPECT_EQ(mask & ~all, 0u);
}

// ---------------------------------------------------------------------------
// resolve_capability_mask
// ---------------------------------------------------------------------------
TEST(CapabilityResolveTest, EmptyListsYieldTheDefaultSet) {
  const mc::SecurityConfig sec;
  const mc::Expected<std::uint64_t> mask = mc::resolve_capability_mask(sec);
  ASSERT_TRUE(mask.has_value());
  EXPECT_EQ(*mask, mc::default_capability_mask());
}

TEST(CapabilityResolveTest, DropRemovesFromTheDefaultSet) {
  const mc::SecurityConfig sec = sec_with({"CAP_CHOWN", "net_raw"}, {});
  const mc::Expected<std::uint64_t> mask = mc::resolve_capability_mask(sec);
  ASSERT_TRUE(mask.has_value());
  EXPECT_EQ(*mask & bit(CAP_CHOWN), 0u);
  EXPECT_EQ(*mask & bit(CAP_NET_RAW), 0u);
  // Untouched entries survive.
  EXPECT_NE(*mask & bit(CAP_NET_BIND_SERVICE), 0u);
}

TEST(CapabilityResolveTest, AddGrantsSomethingOutsideTheDefaultSet) {
  ASSERT_EQ(mc::default_capability_mask() & bit(CAP_SYS_PTRACE), 0u);
  const mc::SecurityConfig sec = sec_with({}, {"SYS_PTRACE"});
  const mc::Expected<std::uint64_t> mask = mc::resolve_capability_mask(sec);
  ASSERT_TRUE(mask.has_value());
  EXPECT_NE(*mask & bit(CAP_SYS_PTRACE), 0u);
}

TEST(CapabilityResolveTest, DropThenAddSoAddWinsWhenBothNameTheSameCap) {
  // SecurityConfig documents the order as "drop, then add", and the order is
  // only observable when a capability appears in both lists. Asserting it
  // here pins the documented behaviour: the more specific request (add) wins,
  // rather than the result depending on vector iteration order.
  const mc::SecurityConfig sec = sec_with({"CAP_NET_RAW"}, {"CAP_NET_RAW"});
  const mc::Expected<std::uint64_t> mask = mc::resolve_capability_mask(sec);
  ASSERT_TRUE(mask.has_value());
  EXPECT_NE(*mask & bit(CAP_NET_RAW), 0u)
      << "add must be applied after drop, so add wins";
}

TEST(CapabilityResolveTest, DropAllClearsEverything) {
  const mc::SecurityConfig sec = sec_with({"ALL"}, {});
  const mc::Expected<std::uint64_t> mask = mc::resolve_capability_mask(sec);
  ASSERT_TRUE(mask.has_value());
  EXPECT_EQ(*mask, 0u);
}

TEST(CapabilityResolveTest, DropAllThenAddOneKeepsExactlyThatOne) {
  // The idiomatic hardening recipe: --cap-drop=ALL --cap-add=NET_BIND_SERVICE.
  const mc::SecurityConfig sec = sec_with({"ALL"}, {"CAP_NET_BIND_SERVICE"});
  const mc::Expected<std::uint64_t> mask = mc::resolve_capability_mask(sec);
  ASSERT_TRUE(mask.has_value());
  EXPECT_EQ(*mask, bit(CAP_NET_BIND_SERVICE));
}

TEST(CapabilityResolveTest, AddAllSetsEveryKnownCapability) {
  const int count = known_capability_count();
  const std::uint64_t all =
      (count == 64) ? ~std::uint64_t{0} : (bit(count) - 1);

  const mc::SecurityConfig sec = sec_with({}, {"cap_all"});
  const mc::Expected<std::uint64_t> mask = mc::resolve_capability_mask(sec);
  ASSERT_TRUE(mask.has_value());
  EXPECT_EQ(*mask, all);
  EXPECT_NE(*mask & bit(CAP_SYS_ADMIN), 0u);
}

TEST(CapabilityResolveTest, PrivilegedKeepsEverythingAndIgnoresTheLists) {
  const int count = known_capability_count();
  const std::uint64_t all =
      (count == 64) ? ~std::uint64_t{0} : (bit(count) - 1);

  mc::SecurityConfig sec = sec_with({"ALL"}, {});
  sec.privileged = true;
  const mc::Expected<std::uint64_t> mask = mc::resolve_capability_mask(sec);
  ASSERT_TRUE(mask.has_value());
  // --privileged is the documented escape hatch, so cap_drop=ALL is
  // irrelevant rather than contradictory. The alternative - letting the lists
  // narrow a privileged container - would make "privileged" mean two
  // different things depending on which flags accompanied it.
  EXPECT_EQ(*mask, all);
}

TEST(CapabilityResolveTest, UnknownNameInEitherListIsAnError) {
  const mc::Expected<std::uint64_t> bad_drop =
      mc::resolve_capability_mask(sec_with({"CAP_NOPE"}, {}));
  ASSERT_FALSE(bad_drop.has_value());
  EXPECT_EQ(bad_drop.error().op(), mc::Op::ValidateConfig);

  const mc::Expected<std::uint64_t> bad_add =
      mc::resolve_capability_mask(sec_with({}, {"CAP_NOPE"}));
  ASSERT_FALSE(bad_add.has_value());
  EXPECT_EQ(bad_add.error().op(), mc::Op::ValidateConfig);

  // A typo in --cap-drop is just as dangerous as one in --cap-add: silently
  // ignoring it leaves the capability in place.
  EXPECT_NE(bad_drop.error().message().find("CAP_NOPE"), std::string::npos);
}

TEST(CapabilityResolveTest, PrivilegedShortCircuitsBeforeNameValidation) {
  // Documents, rather than endorses, the current ordering: privileged returns
  // before either list is walked, so an unknown name in cap_add is not
  // reported. It cannot change the outcome (everything is kept either way),
  // but ContainerConfig::validate() is the layer that must still catch the
  // typo for the user's benefit.
  mc::SecurityConfig sec = sec_with({}, {"CAP_NOPE"});
  sec.privileged = true;
  EXPECT_TRUE(mc::resolve_capability_mask(sec).has_value());
}

// ---------------------------------------------------------------------------
// seccomp
// ---------------------------------------------------------------------------
TEST(SeccompAvailabilityTest, AgreesWithTheCompileDefinition) {
  // seccomp_available() exists so the CLI can say "this build has no
  // libseccomp" instead of failing obscurely later. If it ever disagreed with
  // the macro the whole diagnostic would be a lie.
#if MC_ENABLE_SECCOMP
  EXPECT_TRUE(mc::seccomp_available());
#else
  EXPECT_FALSE(mc::seccomp_available());
#endif
}

namespace {

// ChildContext carries a 16KB seccomp instruction buffer plus a 64KB arena,
// so it goes on the heap rather than a test stack frame.
std::unique_ptr<mc::ChildContext> fresh_context() {
  auto ctx = std::make_unique<mc::ChildContext>();
  // Pre-set to true so "left false" assertions prove the function cleared it
  // rather than merely never touching a default-false field.
  ctx->install_seccomp = true;
  ctx->seccomp_insn_count = 1234;
  return ctx;
}

}  // namespace

TEST(SeccompProgramTest, ModeOffLeavesInstallSeccompFalse) {
  mc::SecurityConfig sec;
  sec.seccomp = mc::SeccompMode::Off;
  auto ctx = fresh_context();

  const mc::Expected<void> r = mc::build_seccomp_program(sec, *ctx);
  ASSERT_TRUE(r.has_value());
  EXPECT_FALSE(ctx->install_seccomp);
}

TEST(SeccompProgramTest, ModeOffSucceedsEvenWithoutLibseccomp) {
  // --seccomp=off must work on a build with no libseccomp; the Unsupported
  // error is reserved for a filter that was actually asked for.
  mc::SecurityConfig sec;
  sec.seccomp = mc::SeccompMode::Off;
  auto ctx = fresh_context();
  EXPECT_TRUE(mc::build_seccomp_program(sec, *ctx).has_value());
}

TEST(SeccompProgramTest, PrivilegedLeavesInstallSeccompFalse) {
  // A filter is meaningless when the process keeps CAP_SYS_ADMIN: it can call
  // seccomp(2) again with a permissive filter, or simply use the capability
  // directly. Installing one anyway would advertise protection that is not
  // there, which is worse than declining it.
  mc::SecurityConfig sec;
  sec.seccomp = mc::SeccompMode::Default;
  sec.privileged = true;
  auto ctx = fresh_context();

  const mc::Expected<void> r = mc::build_seccomp_program(sec, *ctx);
  ASSERT_TRUE(r.has_value());
  EXPECT_FALSE(ctx->install_seccomp);
}

TEST(SeccompProgramTest, DefaultModeBuildsAProgramOrReportsUnsupported) {
  mc::SecurityConfig sec;
  sec.seccomp = mc::SeccompMode::Default;
  sec.privileged = false;
  auto ctx = fresh_context();

  const mc::Expected<void> r = mc::build_seccomp_program(sec, *ctx);

#if MC_ENABLE_SECCOMP
  ASSERT_TRUE(r.has_value()) << r.error().message();
  EXPECT_TRUE(ctx->install_seccomp);
  EXPECT_GT(ctx->seccomp_insn_count, 0u);
  // The instruction buffer in ChildContext is fixed-size, and the child
  // memcpy's straight into it; a program that did not fit would be a buffer
  // overrun, so the builder must refuse rather than truncate.
  EXPECT_LE(ctx->seccomp_insn_count, mc::kMaxSeccompInsns);
#else
  // No libseccomp: refusing is the only honest answer. Silently running the
  // container unfiltered would give the user a container they believe is
  // sandboxed and is not.
  ASSERT_FALSE(r.has_value());
  EXPECT_EQ(r.error().op(), mc::Op::InstallSeccomp);
  EXPECT_FALSE(ctx->install_seccomp);
#endif
}

#if MC_ENABLE_SECCOMP
TEST(SeccompProgramTest, DefaultModeIsDeterministic) {
  // Two builds of the same profile must produce byte-identical BPF. A
  // difference would mean the deny list depends on ambient state, which would
  // make "what does --seccomp=default block" unanswerable.
  mc::SecurityConfig sec;
  sec.seccomp = mc::SeccompMode::Default;
  auto a = fresh_context();
  auto b = fresh_context();

  ASSERT_TRUE(mc::build_seccomp_program(sec, *a).has_value());
  ASSERT_TRUE(mc::build_seccomp_program(sec, *b).has_value());
  ASSERT_EQ(a->seccomp_insn_count, b->seccomp_insn_count);
  EXPECT_EQ(0, std::memcmp(a->seccomp_insns, b->seccomp_insns,
                           a->seccomp_insn_count * 8));
}

TEST(SeccompProgramTest, ProfileModeMissingFileIsAnError) {
  // A path that does not exist must fail loudly rather than silently falling
  // back to the built-in profile - falling back would mean the container
  // runs with different filtering than the user asked for and no indication
  // anything was wrong.
  mc::SecurityConfig sec;
  sec.seccomp = mc::SeccompMode::Profile;
  sec.seccomp_profile_path = "/nonexistent/mc-test-profile-does-not-exist";
  auto ctx = fresh_context();

  const mc::Expected<void> r = mc::build_seccomp_program(sec, *ctx);
  ASSERT_FALSE(r.has_value());
  EXPECT_EQ(r.error().op(), mc::Op::InstallSeccomp);
}

TEST(SeccompProgramTest, ProfileModeEmptyFileIsAnError) {
  // A file with nothing but comments and blank lines names zero syscalls to
  // deny; installing that would be an allow-everything filter presented to
  // the user as "your seccomp profile is active." That must fail, not
  // silently do nothing.
  TempFile profile(
      "# nothing here\n"
      "\n"
      "   \n");
  mc::SecurityConfig sec;
  sec.seccomp = mc::SeccompMode::Profile;
  sec.seccomp_profile_path = profile.path();
  auto ctx = fresh_context();

  const mc::Expected<void> r = mc::build_seccomp_program(sec, *ctx);
  ASSERT_FALSE(r.has_value());
  EXPECT_EQ(r.error().op(), mc::Op::InstallSeccomp);
}

TEST(SeccompProgramTest, ProfileModeBuildsAProgramFromACustomFile) {
  // The whole feature: a real file naming real syscalls compiles to a real
  // BPF program, the same way --seccomp=default does.
  TempFile profile(
      "# deny just these two\n"
      "ptrace\n"
      "\n"
      "reboot  # trailing comment\n");
  mc::SecurityConfig sec;
  sec.seccomp = mc::SeccompMode::Profile;
  sec.seccomp_profile_path = profile.path();
  auto ctx = fresh_context();

  const mc::Expected<void> r = mc::build_seccomp_program(sec, *ctx);
  ASSERT_TRUE(r.has_value()) << r.error().message();
  EXPECT_TRUE(ctx->install_seccomp);
  EXPECT_GT(ctx->seccomp_insn_count, 0u);
  EXPECT_LE(ctx->seccomp_insn_count, mc::kMaxSeccompInsns);
}

TEST(SeccompProgramTest, ProfileModeSkipsUnknownSyscallNamesRatherThanFailing) {
  // Same tolerance the built-in list has always had: a name that does not
  // resolve on this architecture (typo, or a syscall from a different arch)
  // is dropped rather than aborting the whole profile - as long as at least
  // one real syscall remains, which "ptrace" here guarantees.
  TempFile profile("ptrace\nnot_a_real_syscall_name\n");
  mc::SecurityConfig sec;
  sec.seccomp = mc::SeccompMode::Profile;
  sec.seccomp_profile_path = profile.path();
  auto ctx = fresh_context();

  const mc::Expected<void> r = mc::build_seccomp_program(sec, *ctx);
  ASSERT_TRUE(r.has_value()) << r.error().message();
  EXPECT_TRUE(ctx->install_seccomp);
}

TEST(SeccompProgramTest, ProfileModeIsDeterministic) {
  TempFile profile("ptrace\nreboot\nunshare\n");
  mc::SecurityConfig sec;
  sec.seccomp = mc::SeccompMode::Profile;
  sec.seccomp_profile_path = profile.path();
  auto a = fresh_context();
  auto b = fresh_context();

  ASSERT_TRUE(mc::build_seccomp_program(sec, *a).has_value());
  ASSERT_TRUE(mc::build_seccomp_program(sec, *b).has_value());
  ASSERT_EQ(a->seccomp_insn_count, b->seccomp_insn_count);
  EXPECT_EQ(0, std::memcmp(a->seccomp_insns, b->seccomp_insns,
                           a->seccomp_insn_count * 8));
}
#endif  // MC_ENABLE_SECCOMP
