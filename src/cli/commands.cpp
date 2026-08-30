// SPDX-License-Identifier: MIT
//
// MiniContainer - CLI: ParsedCommand -> exit code.
//
// This file is the seam between the pure parser (src/cli/parser.cpp, which
// makes no syscalls) and the container runtime (src/runtime/, which does not
// exist yet). Keeping the seam explicit is the point: the parser can be unit
// tested with no privileges at all, and this file is the only place that has
// to change when the Runtime class lands.
//
// Until then every verb that would need a runtime reports "not yet\n//
// implemented" and exits kExitNotImplemented. That is deliberately NOT exit 1:
// a script that shells out to `minicontainer` can tell "the feature is\n//
// missing" apart from "the operation was attempted and failed", and the
// integration tests assert on the distinction.
//
// THE EXIT CODE MAP
// -----------------
//   0   success
//   1   the operation was attempted and failed
//   2   the command line or the configuration was rejected (usage error)
//   3   the host kernel cannot do what was asked (Op::Unsupported)
//   90  recognised, parsed, but no runtime implementation exists yet
//   128+n  the container's entrypoint was killed by signal n
//          (ExitStatus::to_shell_code(); produced once `run` works, not here)
//
// A container that exits non-zero is NOT a minicontainer failure: `run`
// forwards the entrypoint's own status, exactly like docker run does, so
// codes 1-127 coming out of a successful `run` belong to the guest process
// and not to us.
#include <unistd.h>

#include <cstdio>
#include <string>
#include <string_view>

#include "minicontainer/cli.h"
#include "minicontainer/config.h"
#include "minicontainer/errors.h"
#include "minicontainer/logging.h"
#include "minicontainer/runtime.h"

#ifndef MC_VERSION_STRING
#define MC_VERSION_STRING "0.0.0-unknown"
#endif

namespace mc {
namespace {

constexpr int kExitSuccess = 0;
constexpr int kExitFailure = 1;
constexpr int kExitUsage = 2;
constexpr int kExitUnsupported = 3;

// The inverse of command_name(). Used only for `help <topic>` and for the
// `<cmd> -h` path, where the parser hands us Command::Help plus the original
// subcommand name in `target`.
bool command_from_name(std::string_view name, Command& out) noexcept {
  static constexpr Command kAll[] = {
      Command::Run,   Command::Create, Command::Start, Command::Stop,
      Command::Kill,  Command::Exec,   Command::Ps,    Command::Inspect,
      Command::Stats, Command::Logs,   Command::Rm,    Command::Version,
      Command::Help,
  };
  for (Command c : kAll) {
    if (name == command_name(c)) {
      out = c;
      return true;
    }
  }
  return false;
}

// Errors raised while deciding *what* to do map to a usage exit; errors raised
// while doing it map to a failure exit. The parser only ever produces the
// former, but validate() runs on the runtime side too, so the mapping lives
// here rather than in main().
int exit_code_for(const Error& e) noexcept {
  switch (e.op()) {
    case Op::ParseArgs:
    case Op::ParseConfig:
    case Op::ValidateConfig:
    case Op::ValidateRootfs:
      return kExitUsage;
    case Op::Unsupported:
      return kExitUnsupported;
    default:
      return kExitFailure;
  }
}

void print_version() {
  std::fputs("minicontainer " MC_VERSION_STRING "\n", stdout);
  // The build-time facts a bug report needs. Kept on separate lines so
  // `minicontainer version | head -1` stays a clean version string.
  std::fprintf(stdout, "  seccomp support: %s\n",
               MC_ENABLE_SECCOMP ? "yes" : "no");
  std::fprintf(stdout, "  built: %s %s\n", __DATE__, __TIME__);
}

// `help`, `help <cmd>`, and `<cmd> -h` all land here. An unrecognised topic is
// a usage error - silently printing the general banner would hide the typo.
int run_help(const ParsedCommand& parsed) {
  if (parsed.target.empty()) {
    std::fputs(usage_text().c_str(), stdout);
    return kExitSuccess;
  }
  Command topic = Command::Help;
  if (!command_from_name(parsed.target, topic)) {
    std::fprintf(stderr, "minicontainer: unknown help topic '%s'\n\n",
                 parsed.target.c_str());
    std::fputs(usage_text().c_str(), stderr);
    return kExitUsage;
  }
  std::fputs(command_usage(topic).c_str(), stdout);
  return kExitSuccess;
}

// Reports a failed operation the same way everywhere: the Error's own
// message, which already names the operation and the errno, plus nothing else.
// Prefixing with the command name would duplicate what op_description already
// says.
int report(const Error& e) {
  std::fprintf(stderr, "minicontainer: %s\n", e.message().c_str());
  return exit_code_for(e);
}

}  // namespace

int dispatch_command(const ParsedCommand& parsed) {
  // An explicit --log-level always beats MINICONTAINER_LOG, which main() has
  // already applied. Doing it here rather than in main() means anything
  // driving dispatch_command() directly (the tests, a future embedder) gets
  // the same behaviour.
  if (parsed.log_level_set) {
    Logger::instance().set_level(parsed.log_level);
  }

  switch (parsed.command) {
    case Command::Version:
      print_version();
      return kExitSuccess;

    case Command::Help:
      return run_help(parsed);

    case Command::Run:
    case Command::Create: {
      // parse_run_or_create() already defaulted and validated this config, so
      // the work here is turning a ParsedCommand into a container. Runtime
      // re-validates for the callers that did not come from the parser.
      ContainerConfig config = parsed.config;
      config.apply_defaults();

      Runtime runtime{RuntimePaths::from_env()};
      if (parsed.command == Command::Create) {
        Expected<std::string> id = runtime.create(config);
        if (!id) {
          return report(id.error());
        }
        std::fprintf(stdout, "%s\n", id->c_str());
        return kExitSuccess;
      }

      Expected<int> code = runtime.run(config);
      if (!code) {
        return report(code.error());
      }
      // The entrypoint's own status, forwarded: `run ... /bin/false` exits 1
      // because the guest did, not because minicontainer failed.
      return *code;
    }

    case Command::Start: {
      Runtime runtime{RuntimePaths::from_env()};
      Expected<int> code = runtime.start(parsed.target, true);
      if (!code) {
        return report(code.error());
      }
      return *code;
    }

    case Command::Stop: {
      Runtime runtime{RuntimePaths::from_env()};
      if (Expected<void> r =
              runtime.stop(parsed.target, parsed.stop_timeout_sec);
          !r) {
        return report(r.error());
      }
      std::fprintf(stdout, "%s\n", parsed.target.c_str());
      return kExitSuccess;
    }

    case Command::Kill: {
      Runtime runtime{RuntimePaths::from_env()};
      if (Expected<void> r = runtime.kill(parsed.target, parsed.signal); !r) {
        return report(r.error());
      }
      std::fprintf(stdout, "%s\n", parsed.target.c_str());
      return kExitSuccess;
    }

    case Command::Exec: {
      Runtime runtime{RuntimePaths::from_env()};
      Expected<int> code = runtime.exec(parsed.target, parsed.exec_args,
                                        parsed.exec_env, parsed.exec_workdir);
      if (!code) {
        return report(code.error());
      }
      return *code;
    }

    case Command::Ps: {
      Runtime runtime{RuntimePaths::from_env()};
      Expected<std::vector<ContainerState>> states = runtime.ps(parsed.all);
      if (!states) {
        return report(states.error());
      }
      if (parsed.json) {
        JsonArray arr;
        for (const ContainerState& s : *states) {
          arr.push_back(s.to_json());
        }
        std::fprintf(stdout, "%s\n", Json(std::move(arr)).dump(2).c_str());
      } else {
        std::fputs(format_ps_table(*states).c_str(), stdout);
      }
      return kExitSuccess;
    }

    case Command::Inspect: {
      Runtime runtime{RuntimePaths::from_env()};
      Expected<ContainerState> state = runtime.inspect(parsed.target);
      if (!state) {
        return report(state.error());
      }
      std::fputs(format_inspect(*state, parsed.json).c_str(), stdout);
      return kExitSuccess;
    }

    case Command::Stats: {
      Runtime runtime{RuntimePaths::from_env()};
      Expected<ContainerState> state = runtime.inspect(parsed.target);
      if (!state) {
        return report(state.error());
      }
      Expected<CgroupStats> st = runtime.stats(parsed.target);
      if (!st) {
        return report(st.error());
      }
      std::fputs(format_stats(*state, *st, parsed.json).c_str(), stdout);
      return kExitSuccess;
    }

    case Command::Rm: {
      Runtime runtime{RuntimePaths::from_env()};
      if (Expected<void> r = runtime.remove(parsed.target, parsed.force); !r) {
        return report(r.error());
      }
      std::fprintf(stdout, "%s\n", parsed.target.c_str());
      return kExitSuccess;
    }

    case Command::Logs: {
      Runtime runtime{RuntimePaths::from_env()};
      if (Expected<void> r =
              runtime.logs(parsed.target, parsed.follow, STDOUT_FILENO);
          !r) {
        return report(r.error());
      }
      return kExitSuccess;
    }
  }

  // Unreachable for any value of the enum; present because a Command read from
  // a corrupted state file some day will not be one of the above.
  std::fputs("minicontainer: internal error: unhandled command\n", stderr);
  return kExitFailure;
}

}  // namespace mc
