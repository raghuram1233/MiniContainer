// SPDX-License-Identifier: MIT
//
// Unit tests for the CLI parser and dispatcher.
//
// Everything here runs unprivileged: parse_args() makes no syscalls, and the
// only commands dispatch_command() will actually execute are Version and Help.
// That is the whole reason the parser was kept pure - see cli.h's header
// comment - and it is why this file is in tests/unit/ rather than
// tests/integration/.
//
// Tests drive parse_args(), not parse_command_line(), so no test has to
// fabricate a char**. The one exception is the argv[0]-skipping test, which
// exists precisely to prove parse_command_line() drops the program name.
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <string>
#include <vector>

#include "minicontainer/cli.h"
#include "minicontainer/config.h"
#include "minicontainer/errors.h"

#include <gtest/gtest.h>

namespace mc {
namespace {

// Parses or fails the test with the parser's own message, which is far more
// useful on a regression than a bare "expected true".
ParsedCommand ParseOk(const std::vector<std::string>& args) {
  Expected<ParsedCommand> r = parse_args(args);
  if (!r) {
    ADD_FAILURE() << "expected parse to succeed, got: " << r.error().message();
    return ParsedCommand{};
  }
  return std::move(r).value();
}

Error ParseErr(const std::vector<std::string>& args) {
  Expected<ParsedCommand> r = parse_args(args);
  if (r) {
    ADD_FAILURE() << "expected parse to fail, but it succeeded with command "
                  << command_name(r->command);
    return Error{};
  }
  return std::move(r).error();
}

// A rootfs path and entrypoint that satisfy ContainerConfig::validate(), which
// parse_run_or_create() runs before returning. Validation is pure - it never
// looks at the filesystem - so the path need not exist.
std::vector<std::string> RunArgs(std::vector<std::string> flags) {
  std::vector<std::string> args{"run"};
  for (auto& f : flags)
    args.push_back(std::move(f));
  args.push_back("--rootfs");
  args.push_back("/tmp/rootfs");
  args.push_back("/bin/sh");
  return args;
}

// Every verb, in one place, so the "does this hold for all commands" tests
// cannot silently miss one that was added later.
constexpr Command kAllCommands[] = {
    Command::Run,   Command::Create, Command::Start, Command::Stop,
    Command::Kill,  Command::Exec,   Command::Ps,    Command::Inspect,
    Command::Stats, Command::Logs,   Command::Rm,    Command::Version,
    Command::Help,
};

// ---------------------------------------------------------------------------
// Command selection and the no-argument case.
// ---------------------------------------------------------------------------
TEST(CliCommandTest, NoArgumentsIsHelpNotAnError) {
  // A bare `minicontainer` prints usage and exits 0. Making this a parse error
  // would mean `minicontainer | less` reported failure to a shell.
  ParsedCommand pc = ParseOk({});
  EXPECT_EQ(pc.command, Command::Help);
  EXPECT_TRUE(pc.target.empty());
}

TEST(CliCommandTest, EveryVerbIsRecognised) {
  EXPECT_EQ(ParseOk({"ps"}).command, Command::Ps);
  EXPECT_EQ(ParseOk({"start", "c1"}).command, Command::Start);
  EXPECT_EQ(ParseOk({"stop", "c1"}).command, Command::Stop);
  EXPECT_EQ(ParseOk({"kill", "c1"}).command, Command::Kill);
  EXPECT_EQ(ParseOk({"inspect", "c1"}).command, Command::Inspect);
  EXPECT_EQ(ParseOk({"stats"}).command, Command::Stats);
  EXPECT_EQ(ParseOk({"logs", "c1"}).command, Command::Logs);
  EXPECT_EQ(ParseOk({"rm", "c1"}).command, Command::Rm);
  EXPECT_EQ(ParseOk({"exec", "c1", "/bin/sh"}).command, Command::Exec);
  EXPECT_EQ(ParseOk({"version"}).command, Command::Version);
  EXPECT_EQ(ParseOk({"help"}).command, Command::Help);
  EXPECT_EQ(ParseOk(RunArgs({})).command, Command::Run);
  EXPECT_EQ(ParseOk({"create", "--rootfs", "/tmp/rootfs", "/bin/sh"}).command,
            Command::Create);
}

TEST(CliCommandTest, CommandNameRoundTrips) {
  // command_name() is what error messages and `help <topic>` key off, so it
  // must agree with the tokens the parser accepts for every verb.
  for (Command c : kAllCommands) {
    const std::string name = command_name(c);
    EXPECT_FALSE(name.empty()) << "command has no name";
    EXPECT_EQ(ParseOk({"help", name}).target, name);
  }
}

TEST(CliCommandTest, UnknownCommandSuggestsTheNearestOne) {
  Error e = ParseErr({"pss"});
  EXPECT_EQ(e.op(), Op::ParseArgs);
  EXPECT_NE(e.message().find("did you mean"), std::string::npos) << e.message();
  EXPECT_NE(e.message().find("ps"), std::string::npos) << e.message();
}

TEST(CliCommandTest, UnknownCommandWithNoNearMatchListsTheAlternatives) {
  Error e = ParseErr({"zzzzzzzz"});
  EXPECT_NE(e.message().find("expected one of"), std::string::npos)
      << e.message();
}

TEST(CliCommandTest, ArgvZeroIsSkipped) {
  const char* argv[] = {"/usr/local/bin/minicontainer", "version", nullptr};
  Expected<ParsedCommand> r = parse_command_line(2, argv);
  ASSERT_TRUE(r) << r.error().message();
  EXPECT_EQ(r->command, Command::Version);
}

// ---------------------------------------------------------------------------
// Global flags.
// ---------------------------------------------------------------------------
TEST(CliGlobalFlagTest, HelpAndVersionShortCircuit) {
  EXPECT_EQ(ParseOk({"-h"}).command, Command::Help);
  EXPECT_EQ(ParseOk({"--help"}).command, Command::Help);
  EXPECT_EQ(ParseOk({"-v"}).command, Command::Version);
  EXPECT_EQ(ParseOk({"--version"}).command, Command::Version);
}

TEST(CliGlobalFlagTest, LogLevelIsCarriedOntoTheSubcommand) {
  // The global flag is parsed before the subcommand is even identified, so the
  // parser has to copy it onto the ParsedCommand the subcommand produced.
  // Losing it here would silently ignore --log-level for every verb.
  ParsedCommand pc = ParseOk({"--log-level", "debug", "ps"});
  EXPECT_EQ(pc.command, Command::Ps);
  EXPECT_TRUE(pc.log_level_set);
  EXPECT_EQ(pc.log_level, LogLevel::Debug);
}

TEST(CliGlobalFlagTest, LogLevelAcceptsAttachedValue) {
  ParsedCommand pc = ParseOk({"--log-level=trace", "ps"});
  EXPECT_TRUE(pc.log_level_set);
  EXPECT_EQ(pc.log_level, LogLevel::Trace);
}

TEST(CliGlobalFlagTest, LogLevelDefaultsToInfoAndIsMarkedUnset) {
  ParsedCommand pc = ParseOk({"ps"});
  EXPECT_FALSE(pc.log_level_set);
  EXPECT_EQ(pc.log_level, LogLevel::Info);
}

TEST(CliGlobalFlagTest, MissingLogLevelValueIsAnError) {
  Error e = ParseErr({"--log-level"});
  EXPECT_EQ(e.op(), Op::ParseArgs);
}

TEST(CliGlobalFlagTest, UnknownGlobalFlagIsRejected) {
  Error e = ParseErr({"--nope", "ps"});
  EXPECT_EQ(e.op(), Op::ParseArgs);
  EXPECT_NE(e.message().find("--nope"), std::string::npos) << e.message();
}

// ---------------------------------------------------------------------------
// run / create: resources.
// ---------------------------------------------------------------------------
TEST(CliRunTest, MemorySuffixesAre1024Based) {
  ParsedCommand pc = ParseOk(RunArgs({"--memory", "256M"}));
  ASSERT_TRUE(pc.config.resources.memory_bytes.has_value());
  EXPECT_EQ(*pc.config.resources.memory_bytes, 256ULL * 1024 * 1024);
}

TEST(CliRunTest, MemoryAcceptsAttachedValueAndPlainBytes) {
  EXPECT_EQ(*ParseOk(RunArgs({"--memory=1G"})).config.resources.memory_bytes,
            1024ULL * 1024 * 1024);
  EXPECT_EQ(
      *ParseOk(RunArgs({"--memory", "1048576"})).config.resources.memory_bytes,
      1048576ULL);
}

TEST(CliRunTest, MalformedMemoryIsRejected) {
  EXPECT_EQ(ParseErr(RunArgs({"--memory", "banana"})).op(), Op::ParseArgs);
  EXPECT_EQ(ParseErr(RunArgs({"--memory", "-1"})).op(), Op::ParseArgs);
}

TEST(CliRunTest, FractionalCpusSurvive) {
  // 0.5 must not be truncated to 0 on the way to cpu.max - that would silently
  // turn "half a core" into "no quota at all".
  ParsedCommand pc = ParseOk(RunArgs({"--cpus", "0.5"}));
  ASSERT_TRUE(pc.config.resources.cpus.has_value());
  EXPECT_DOUBLE_EQ(*pc.config.resources.cpus, 0.5);

  auto cpu_max = pc.config.resources.cpu_max_value();
  ASSERT_TRUE(cpu_max.has_value());
  EXPECT_EQ(*cpu_max, "50000 100000");
}

TEST(CliRunTest, PidsAndCpusetAreCarried) {
  ParsedCommand pc = ParseOk(RunArgs({"--pids", "64", "--cpuset-cpus", "0-3"}));
  ASSERT_TRUE(pc.config.resources.pids_max.has_value());
  EXPECT_EQ(*pc.config.resources.pids_max, 64ULL);
  ASSERT_TRUE(pc.config.resources.cpuset_cpus.has_value());
  EXPECT_EQ(*pc.config.resources.cpuset_cpus, "0-3");
}

TEST(CliRunTest, UnsetLimitsStayNullopt) {
  // std::nullopt means "never write this cgroup file"; a zero default would
  // mean "write 0", which for pids.max forbids the container from forking.
  ParsedCommand pc = ParseOk(RunArgs({}));
  EXPECT_FALSE(pc.config.resources.memory_bytes.has_value());
  EXPECT_FALSE(pc.config.resources.cpus.has_value());
  EXPECT_FALSE(pc.config.resources.pids_max.has_value());
  EXPECT_FALSE(pc.config.resources.cpuset_cpus.has_value());
}

// ---------------------------------------------------------------------------
// run / create: networking.
// ---------------------------------------------------------------------------
TEST(CliRunTest, NetworkModeIsParsed) {
  EXPECT_EQ(ParseOk(RunArgs({"--network", "bridge"})).config.network.mode,
            NetworkMode::Bridge);
  EXPECT_EQ(ParseOk(RunArgs({"--network", "host"})).config.network.mode,
            NetworkMode::Host);
  EXPECT_EQ(ParseOk(RunArgs({"--network", "none"})).config.network.mode,
            NetworkMode::None);
}

TEST(CliRunTest, PortPublishingIsRepeatableAndDefaultsToTcp) {
  ParsedCommand pc =
      ParseOk(RunArgs({"-p", "8080:80", "--publish", "5353:53/udp"}));
  ASSERT_EQ(pc.config.network.ports.size(), 2U);
  EXPECT_EQ(pc.config.network.ports[0].host_port, 8080);
  EXPECT_EQ(pc.config.network.ports[0].container_port, 80);
  EXPECT_EQ(pc.config.network.ports[0].protocol, "tcp");
  EXPECT_EQ(pc.config.network.ports[1].host_port, 5353);
  EXPECT_EQ(pc.config.network.ports[1].protocol, "udp");
}

TEST(CliRunTest, MalformedPortIsRejected) {
  EXPECT_EQ(ParseErr(RunArgs({"-p", "8080"})).op(), Op::ParseArgs);
  EXPECT_EQ(ParseErr(RunArgs({"-p", "99999:80"})).op(), Op::ParseArgs);
}

// ---------------------------------------------------------------------------
// run / create: the flag/positional boundary. This is where an argv parser is
// most likely to be wrong, so it gets the most tests.
// ---------------------------------------------------------------------------
TEST(CliRunTest, RootfsFormPutsEveryTailTokenInArgs) {
  ParsedCommand pc =
      ParseOk({"run", "--rootfs", "/tmp/rootfs", "/bin/sh", "-c", "echo hi"});
  EXPECT_EQ(pc.config.rootfs_path, "/tmp/rootfs");
  ASSERT_EQ(pc.config.args.size(), 3U);
  EXPECT_EQ(pc.config.args[0], "/bin/sh");
  EXPECT_EQ(pc.config.args[1], "-c");
  EXPECT_EQ(pc.config.args[2], "echo hi");
  EXPECT_TRUE(pc.bundle_path.empty());
}

TEST(CliRunTest, EntrypointFlagsAreNotEatenByTheParser) {
  // The critical case: -it after the entrypoint belongs to the guest, not to
  // minicontainer. Parsing stops at the first non-flag token, so tty must stay
  // false here even though "-t" appears in the command line.
  ParsedCommand pc =
      ParseOk({"run", "--rootfs", "/tmp/rootfs", "/bin/ls", "-it", "/proc"});
  EXPECT_FALSE(pc.config.tty);
  ASSERT_EQ(pc.config.args.size(), 3U);
  EXPECT_EQ(pc.config.args[1], "-it");
}

TEST(CliRunTest, DoubleDashEndsFlagParsing) {
  ParsedCommand pc =
      ParseOk({"run", "--rootfs", "/tmp/rootfs", "--", "/bin/sh", "--login"});
  ASSERT_EQ(pc.config.args.size(), 2U);
  EXPECT_EQ(pc.config.args[0], "/bin/sh");
  EXPECT_EQ(pc.config.args[1], "--login");
}

TEST(CliRunTest, BundleFormTakesTheFirstTailTokenAsThePath) {
  ParsedCommand pc = ParseOk({"run", "/srv/bundle", "/bin/sh"});
  EXPECT_EQ(pc.bundle_path, "/srv/bundle");
  ASSERT_EQ(pc.config.args.size(), 1U);
  EXPECT_EQ(pc.config.args[0], "/bin/sh");
}

TEST(CliRunTest, RootfsWithNoCommandIsAnError) {
  Error e = ParseErr({"run", "--rootfs", "/tmp/rootfs"});
  EXPECT_EQ(e.op(), Op::ParseArgs);
  EXPECT_NE(e.message().find("requires a command"), std::string::npos)
      << e.message();
}

TEST(CliRunTest, NoRootfsAndNoBundleIsAnError) {
  EXPECT_EQ(ParseErr({"run"}).op(), Op::ParseArgs);
}

// ---------------------------------------------------------------------------
// run / create: short flags.
// ---------------------------------------------------------------------------
TEST(CliRunTest, ClusteredShortFlagsAreSplit) {
  ParsedCommand pc = ParseOk(RunArgs({"-itd"}));
  EXPECT_TRUE(pc.interactive);
  EXPECT_TRUE(pc.config.tty);
  EXPECT_TRUE(pc.config.detach);
}

TEST(CliRunTest, ValueTakingShortFlagsAcceptAttachedValues) {
  ParsedCommand pc = ParseOk(RunArgs({"-eKEY=VALUE", "-w/srv", "-v/a:/b:ro"}));
  ASSERT_EQ(pc.config.env.size(), 1U);
  EXPECT_EQ(pc.config.env[0], "KEY=VALUE");
  EXPECT_EQ(pc.config.working_dir, "/srv");
  ASSERT_EQ(pc.config.bind_mounts.size(), 1U);
  EXPECT_EQ(pc.config.bind_mounts[0], "/a:/b:ro");
}

TEST(CliRunTest, UnknownShortFlagIsRejected) {
  EXPECT_EQ(ParseErr(RunArgs({"-Z"})).op(), Op::ParseArgs);
}

TEST(CliRunTest, HelpFlagAnywhereBecomesPerCommandHelp) {
  ParsedCommand pc = ParseOk({"run", "-h"});
  EXPECT_EQ(pc.command, Command::Help);
  EXPECT_EQ(pc.target, "run");
}

// ---------------------------------------------------------------------------
// run / create: security and identity.
// ---------------------------------------------------------------------------
TEST(CliRunTest, CapabilityListsAreRepeatableAndOrdered) {
  ParsedCommand pc =
      ParseOk(RunArgs({"--cap-drop", "ALL", "--cap-add", "NET_BIND_SERVICE",
                       "--cap-add", "CHOWN"}));
  ASSERT_EQ(pc.config.security.cap_drop.size(), 1U);
  EXPECT_EQ(pc.config.security.cap_drop[0], "ALL");
  ASSERT_EQ(pc.config.security.cap_add.size(), 2U);
  EXPECT_EQ(pc.config.security.cap_add[0], "NET_BIND_SERVICE");
  EXPECT_EQ(pc.config.security.cap_add[1], "CHOWN");
}

TEST(CliRunTest, SecurityDefaultsAreTheSafeOnes) {
  ParsedCommand pc = ParseOk(RunArgs({}));
  EXPECT_TRUE(pc.config.security.no_new_privs);
  EXPECT_FALSE(pc.config.security.privileged);
  EXPECT_FALSE(pc.config.security.userns);
  EXPECT_FALSE(pc.config.security.readonly_rootfs);
  EXPECT_EQ(pc.config.security.seccomp, SeccompMode::Default);
}

TEST(CliRunTest, NameAndHostnameAreCarried) {
  ParsedCommand pc = ParseOk(RunArgs({"--name", "web", "--hostname", "web-1"}));
  EXPECT_EQ(pc.config.name, "web");
  EXPECT_EQ(pc.config.hostname, "web-1");
}

TEST(CliRunTest, InvalidNameIsRejectedByValidation) {
  // parse_run_or_create() runs ContainerConfig::validate() before returning,
  // so a bad name is a parse-time failure rather than a runtime surprise.
  Error e = ParseErr(RunArgs({"--name", "bad name/with slash"}));
  EXPECT_EQ(e.op(), Op::ValidateConfig);
}

TEST(CliRunTest, DefaultsAreAppliedSoIdAndHostnameExist) {
  ParsedCommand pc = ParseOk(RunArgs({}));
  EXPECT_FALSE(pc.config.id.empty());
  EXPECT_EQ(pc.config.id.size(), 12U);
  EXPECT_FALSE(pc.config.hostname.empty());
  EXPECT_FALSE(pc.config.name.empty());
}

// ---------------------------------------------------------------------------
// Single-target verbs.
// ---------------------------------------------------------------------------
TEST(CliTargetTest, TargetIsRequiredWhereItMatters) {
  EXPECT_EQ(ParseErr({"start"}).op(), Op::ParseArgs);
  EXPECT_EQ(ParseErr({"stop"}).op(), Op::ParseArgs);
  EXPECT_EQ(ParseErr({"kill"}).op(), Op::ParseArgs);
  EXPECT_EQ(ParseErr({"logs"}).op(), Op::ParseArgs);
  EXPECT_EQ(ParseErr({"rm"}).op(), Op::ParseArgs);
  EXPECT_EQ(ParseErr({"inspect"}).op(), Op::ParseArgs);
}

TEST(CliTargetTest, SecondPositionalIsRejected) {
  Error e = ParseErr({"start", "c1", "c2"});
  EXPECT_NE(e.message().find("unexpected argument"), std::string::npos)
      << e.message();
}

TEST(CliTargetTest, FlagsMayPrecedeOrFollowTheTarget) {
  EXPECT_EQ(ParseOk({"stop", "--time", "30", "c1"}).target, "c1");
  EXPECT_EQ(ParseOk({"stop", "c1", "--time", "30"}).stop_timeout_sec, 30);
}

TEST(CliStopTest, TimeoutDefaultsToTenSeconds) {
  EXPECT_EQ(ParseOk({"stop", "c1"}).stop_timeout_sec, 10);
}

TEST(CliKillTest, SignalDefaultsToSigterm) {
  EXPECT_EQ(ParseOk({"kill", "c1"}).signal, SIGTERM);
}

TEST(CliKillTest, SignalAcceptsNameNumberAndSigPrefix) {
  EXPECT_EQ(ParseOk({"kill", "--signal", "KILL", "c1"}).signal, SIGKILL);
  EXPECT_EQ(ParseOk({"kill", "--signal", "SIGHUP", "c1"}).signal, SIGHUP);
  EXPECT_EQ(ParseOk({"kill", "--signal", "9", "c1"}).signal, SIGKILL);
}

TEST(CliKillTest, UnknownSignalIsRejected) {
  EXPECT_EQ(ParseErr({"kill", "--signal", "SIGNOPE", "c1"}).op(),
            Op::ParseArgs);
}

TEST(CliListTest, BooleanFlagsAreCarried) {
  EXPECT_TRUE(ParseOk({"ps", "-a"}).all);
  EXPECT_TRUE(ParseOk({"ps", "--json"}).json);
  EXPECT_FALSE(ParseOk({"ps"}).all);
  EXPECT_TRUE(ParseOk({"inspect", "--json", "c1"}).json);
  EXPECT_TRUE(ParseOk({"stats", "--no-stream"}).no_stream);
  EXPECT_TRUE(ParseOk({"logs", "-f", "c1"}).follow);
  EXPECT_TRUE(ParseOk({"rm", "-f", "c1"}).force);
}

TEST(CliListTest, PsTakesNoTarget) {
  EXPECT_TRUE(ParseOk({"ps"}).target.empty());
}

// ---------------------------------------------------------------------------
// exec. Its argument split is the other place a parser usually goes wrong:
// everything after the container name belongs to the guest.
// ---------------------------------------------------------------------------
TEST(CliExecTest, TargetThenGuestArgv) {
  ParsedCommand pc = ParseOk({"exec", "c1", "/bin/sh", "-c", "id"});
  EXPECT_EQ(pc.command, Command::Exec);
  EXPECT_EQ(pc.target, "c1");
  ASSERT_EQ(pc.exec_args.size(), 3U);
  EXPECT_EQ(pc.exec_args[0], "/bin/sh");
  EXPECT_EQ(pc.exec_args[1], "-c");
  EXPECT_EQ(pc.exec_args[2], "id");
}

TEST(CliExecTest, GuestFlagsAreNotClaimedByMinicontainer) {
  // -t here is an argument to `ls`, not a request for a TTY.
  ParsedCommand pc = ParseOk({"exec", "c1", "ls", "-t"});
  EXPECT_FALSE(pc.exec_tty);
  ASSERT_EQ(pc.exec_args.size(), 2U);
  EXPECT_EQ(pc.exec_args[1], "-t");
}

TEST(CliExecTest, SessionOverridesComeBeforeTheTarget) {
  ParsedCommand pc = ParseOk(
      {"exec", "-t", "-e", "A=1", "-e", "B=2", "-w", "/srv", "c1", "/bin/sh"});
  EXPECT_TRUE(pc.exec_tty);
  EXPECT_EQ(pc.exec_workdir, "/srv");
  ASSERT_EQ(pc.exec_env.size(), 2U);
  EXPECT_EQ(pc.exec_env[0], "A=1");
  EXPECT_EQ(pc.exec_env[1], "B=2");
  EXPECT_EQ(pc.target, "c1");
}

TEST(CliExecTest, ExecNeverBuildsAContainerConfig) {
  // cli.h documents `config` as populated only for Run/Create. exec's -e/-w
  // deliberately land in exec_env/exec_workdir instead, so nothing downstream
  // mistakes an exec session for a container specification.
  ParsedCommand pc = ParseOk({"exec", "-e", "A=1", "c1", "/bin/sh"});
  EXPECT_TRUE(pc.config.env.empty());
  EXPECT_TRUE(pc.config.rootfs_path.empty());
}

TEST(CliExecTest, MissingTargetOrCommandIsAnError) {
  EXPECT_EQ(ParseErr({"exec"}).op(), Op::ParseArgs);
  EXPECT_EQ(ParseErr({"exec", "c1"}).op(), Op::ParseArgs);
}

// ---------------------------------------------------------------------------
// Usage text. These are contract tests, not prose tests: they assert the text
// mentions every verb, because a verb missing from the banner is invisible.
// ---------------------------------------------------------------------------
TEST(CliUsageTest, BannerListsEveryCommand) {
  const std::string usage = usage_text();
  ASSERT_FALSE(usage.empty());
  for (Command c : kAllCommands) {
    EXPECT_NE(usage.find(command_name(c)), std::string::npos)
        << "usage_text() never mentions '" << command_name(c) << "'";
  }
}

TEST(CliUsageTest, EveryDispatchableCommandHasItsOwnUsage) {
  for (Command c : kAllCommands) {
    if (c == Command::Version || c == Command::Help)
      continue;
    const std::string text = command_usage(c);
    EXPECT_FALSE(text.empty())
        << "command_usage(" << command_name(c) << ") is empty";
    EXPECT_NE(text.find(command_name(c)), std::string::npos)
        << "command_usage(" << command_name(c) << ") does not name itself";
  }
}

// ---------------------------------------------------------------------------
// dispatch_command. Only Version and Help do real work today; everything else
// must report kExitNotImplemented rather than pretending to succeed.
// ---------------------------------------------------------------------------
TEST(CliDispatchTest, VersionAndHelpSucceed) {
  ParsedCommand version;
  version.command = Command::Version;
  EXPECT_EQ(dispatch_command(version), 0);

  ParsedCommand help;
  help.command = Command::Help;
  EXPECT_EQ(dispatch_command(help), 0);

  ParsedCommand topic;
  topic.command = Command::Help;
  topic.target = "run";
  EXPECT_EQ(dispatch_command(topic), 0);
}

TEST(CliDispatchTest, UnknownHelpTopicIsAUsageError) {
  ParsedCommand pc;
  pc.command = Command::Help;
  pc.target = "nosuchcommand";
  EXPECT_EQ(dispatch_command(pc), 2);
}

// A dispatch test must never touch the real /var/lib/minicontainer: it would
// list, and potentially reconcile, the machine's actual containers. Runtime
// reads MINICONTAINER_ROOT through RuntimePaths::from_env(), so redirecting it
// at a scratch directory is what keeps these tests unprivileged and inert.
class DispatchEnv : public ::testing::Test {
 protected:
  void SetUp() override {
    char tmpl[] = "/tmp/mc-cli-test-XXXXXX";
    const char* dir = ::mkdtemp(tmpl);
    ASSERT_NE(dir, nullptr) << "mkdtemp: " << std::strerror(errno);
    root_ = dir;
    ::setenv("MINICONTAINER_ROOT", root_.c_str(), 1);
  }
  void TearDown() override {
    ::unsetenv("MINICONTAINER_ROOT");
    ::rmdir(root_.c_str());
  }
  std::string root_;
};

TEST_F(DispatchEnv, RuntimeBackedCommandsNowReachTheRuntime) {
  // These used to return 90. The runtime exists now, so they run and fail on
  // the real reason - there is no container called "c1" - which is exit 1, not
  // "unimplemented". That distinction is the whole reason 90 is separate, and
  // this test is what proves the transition actually happened.
  const Command runtime_backed[] = {
      Command::Start,   Command::Stop,  Command::Kill, Command::Exec,
      Command::Inspect, Command::Stats, Command::Rm};
  for (Command c : runtime_backed) {
    ParsedCommand pc;
    pc.command = c;
    pc.target = "c1";
    pc.exec_args = {"/bin/true"};  // exec rejects an empty argv first
    const int rc = dispatch_command(pc);
    EXPECT_EQ(rc, 1) << "command: " << command_name(c)
                     << " should report a real failure, not " << rc;
    EXPECT_NE(rc, kExitNotImplemented)
        << "command: " << command_name(c) << " is implemented now";
  }
}

TEST_F(DispatchEnv, PsOnAnEmptyStoreSucceeds) {
  // No containers is not an error - a script doing `ps` in a loop must not see
  // a failure just because nothing is running.
  ParsedCommand pc;
  pc.command = Command::Ps;
  EXPECT_EQ(dispatch_command(pc), 0);
}

TEST_F(DispatchEnv, NoVerbReportsUnimplementedAnyMore) {
  // `logs` was the last verb returning kExitNotImplemented. It is implemented
  // now, so it fails on the real reason - no such container - like every other
  // runtime-backed verb. Exit 90 should no longer be reachable from dispatch
  // at all, and this test is what would catch a regression that reintroduced
  // it silently.
  ParsedCommand pc;
  pc.command = Command::Logs;
  pc.target = "c1";
  const int rc = dispatch_command(pc);
  EXPECT_EQ(rc, 1);
  EXPECT_NE(rc, kExitNotImplemented);
}

TEST_F(DispatchEnv, RunWithAMissingRootfsIsAUsageError) {
  // The rootfs path from RunArgs() does not exist, so validate_rootfs rejects
  // it before anything is created. Exit 2, not a crash and not a half-made
  // container.
  ParsedCommand pc = ParseOk(RunArgs({}));
  EXPECT_EQ(dispatch_command(pc), 2);
}

TEST(CliDispatchTest, RunWithAnInvalidConfigIsAUsageError) {
  // dispatch re-validates rather than trusting its caller, so a config that
  // never went through the parser is still rejected before the runtime sees
  // it. args is empty here, which validate() requires to be non-empty.
  ParsedCommand pc;
  pc.command = Command::Run;
  pc.config.rootfs_path = "/tmp/rootfs";
  EXPECT_EQ(dispatch_command(pc), 2);
}

TEST(CliRunTest, OutOfRangeCpuSharesIsRejectedWithTheValidRange) {
  // cpu.weight accepts 1..10000. A Docker habit like --cpu-shares 262144 used
  // to reach the kernel and fail as a bare EINVAL on a cgroup file, saying
  // nothing about what the valid range was.
  Error e = ParseErr(RunArgs({"--cpu-shares", "262144"}));
  EXPECT_EQ(e.op(), Op::ValidateConfig);
  EXPECT_NE(e.message().find("1 and 10000"), std::string::npos) << e.message();

  EXPECT_TRUE(parse_args(RunArgs({"--cpu-shares", "1024"})).has_value());
}

}  // namespace
}  // namespace mc
