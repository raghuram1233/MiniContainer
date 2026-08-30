// SPDX-License-Identifier: MIT
//
// MiniContainer - CLI: argv -> ParsedCommand.
//
// THE BOUNDARY THAT MATTERS
// --------------------------
// Everything in this header and in src/cli/parser.cpp is pure: it turns argv
// into a validated mc::ContainerConfig plus a chosen subcommand. It never
// creates a namespace, never touches a cgroup, never makes a syscall beyond
// the ones needed to read argv itself. That is what makes the parser
// unit-testable without root - see tests/unit/test_cli.cpp, which links only
// against mc_core and gtest, no privilege required.
//
// src/cli/commands.cpp is the seam where a parsed command meets the runtime.
// The Runtime class does not exist yet (another agent is building it); until
// it does, RuntimeOps below is the entire contract the CLI needs from it, and
// commands.cpp's dispatch prints "not yet implemented" for everything except
// Version and Help.
#pragma once

#include <signal.h>

#include <string>
#include <vector>

#include "minicontainer/config.h"
#include "minicontainer/errors.h"
#include "minicontainer/logging.h"

namespace mc {

// ---------------------------------------------------------------------------
// Command - every verb the CLI understands.
// ---------------------------------------------------------------------------
enum class Command {
  Run,
  Create,
  Start,
  Stop,
  Kill,
  Exec,
  Ps,
  Inspect,
  Stats,
  Logs,
  Rm,
  Version,
  Help,
};

// The single machine-readable token for a command, e.g. "run". Used in error
// messages and tests.
const char* command_name(Command c) noexcept;

// ---------------------------------------------------------------------------
// ParsedCommand - the sole output of parsing. Everything downstream acts on
// this; nothing downstream ever looks at argv again.
// ---------------------------------------------------------------------------
struct ParsedCommand {
  Command command = Command::Help;

  ContainerConfig config;  // populated for Run/Create

  std::string target;                  // container name or id
  std::vector<std::string> exec_args;  // for Exec: argv inside the container

  // Per-command extras.
  int signal = SIGTERM;       // kill
  int stop_timeout_sec = 10;  // stop --time
  bool follow = false;        // logs -f
  bool all = false;           // ps -a
  bool json = false;          // inspect/ps --json
  bool no_stream = false;     // stats --no-stream
  std::string bundle_path;    // run <bundle>/ (OCI-style)
  bool force = false;         // rm -f/--force
  bool interactive =
      false;  // run/create -i/--interactive (kept open, no runtime effect yet)

  // exec has its own -e/-w/-t rather than reusing `config`, because `config`
  // is documented as populated only for Run/Create - exec never builds a
  // full ContainerConfig, just a target plus a few session overrides.
  std::vector<std::string> exec_env;  // exec -e/--env (repeatable)
  std::string exec_workdir;           // exec -w/--workdir
  bool exec_tty = false;              // exec -t/--tty

  LogLevel log_level = LogLevel::Info;
  bool log_level_set =
      false;  // whether --log-level was given on the command line
};

// Parses a real argv (argv[0] is the program name and is skipped). This is
// the entry point main() calls.
Expected<ParsedCommand> parse_command_line(int argc, const char* const argv[]);

// The testable core: parses everything AFTER the program name. All unit
// tests drive this directly so they never have to fabricate a char**.
Expected<ParsedCommand> parse_args(const std::vector<std::string>& args);

// Top-level usage banner, shown by `minicontainer help` / `-h` with no
// subcommand, and on a parse error.
std::string usage_text();

// Per-command usage, shown by `minicontainer help <cmd>` and by `<cmd> -h`.
std::string command_usage(Command c);

// ---------------------------------------------------------------------------
// RuntimeOps - the entire contract the CLI's dispatch layer needs from the
// container runtime. Deliberately tiny and deliberately abstract: the real
// Runtime class (built by another agent) will implement this, and until it
// exists dispatch_command() runs with no implementation at all, reporting
// "not yet implemented" for every command that would need one.
// ---------------------------------------------------------------------------
class RuntimeOps {
 public:
  virtual ~RuntimeOps() = default;
};

// Exit code for a command that is recognised and parsed but has no runtime
// implementation to dispatch to yet.
inline constexpr int kExitNotImplemented = 90;

// Runs a parsed command and returns the process exit code. See
// src/cli/commands.cpp for the ExitStatus/Error -> exit code mapping.
int dispatch_command(const ParsedCommand& parsed);

}  // namespace mc
