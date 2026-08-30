// SPDX-License-Identifier: MIT
//
// MiniContainer - process entry point.
//
// main() stays this small on purpose. It is excluded from the mc_core library
// by the root CMakeLists.txt (a library with a main() in it cannot be linked
// into the test binaries), so anything written here is code the unit tests can
// never reach. Everything worth testing therefore lives in parse_args() and
// dispatch_command(), both of which the tests call directly.
//
// Three things happen here and nowhere else:
//   1. MINICONTAINER_LOG is read, before anything can want to log.
//   2. argv is turned into a ParsedCommand.
//   3. A parse failure is reported and turned into exit 2.
#include <cstdio>

#include "minicontainer/cli.h"
#include "minicontainer/errors.h"
#include "minicontainer/logging.h"

int main(int argc, char* argv[]) {
  // Before the parser runs, so that a parse failure is still logged at
  // whatever level the environment asked for. A --log-level on the command
  // line overrides this later, in dispatch_command().
  mc::init_logging_from_env();

  mc::Expected<mc::ParsedCommand> parsed = mc::parse_command_line(argc, argv);
  if (!parsed) {
    // Usage errors go to stderr and are followed by the banner, so a user who
    // mistyped a flag sees the correct spelling without a second invocation.
    // The exit code matches commands.cpp's kExitUsage; see its header comment
    // for the full map.
    std::fprintf(stderr, "minicontainer: %s\n\n",
                 parsed.error().message().c_str());
    std::fputs(mc::usage_text().c_str(), stderr);
    return 2;
  }

  return mc::dispatch_command(*parsed);
}
