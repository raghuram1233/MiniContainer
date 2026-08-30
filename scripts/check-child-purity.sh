#!/usr/bin/env bash
# check-child-purity.sh - enforce the no-allocation rule in child-side code.
#
# WHAT THIS PROTECTS
# Between clone() and execve() the container process may hold a malloc lock
# inherited from a thread that does not exist in its address space. A single
# allocation there can deadlock it forever, with no diagnostic and no core
# dump - the container simply hangs. logging.h and container.h both state the
# rule; until this script existed nothing enforced it, and it held by code
# review alone.
#
# WHAT IT CHECKS
# Every function whose name begins with `step_` and returns ChildStatus runs in
# that window. This script extracts each such body and rejects the constructs
# that can allocate, take a lock, or throw:
#
#   MC_LOG_*      parent-side logging: formats with ostringstream, takes a mutex
#   std::string   allocates
#   std::vector   allocates
#   new / malloc  allocates
#   snprintf      may allocate internally for some conversions
#   throw         there is no handler, and unwinding here is undefined
#
# MC_CLOG / MC_CLOG_N are the child-safe sinks and are deliberately allowed:
# they do one write(2) of a literal.
#
# WHY FUNCTION BODIES AND NOT WHOLE FILES
# Several translation units legitimately hold both halves. capabilities.cpp
# resolves capability names (parent, allocates freely) *and* applies the
# resulting mask (child, must not). A file-level grep would either fail on
# correct code or have to skip those files entirely - which would leave the
# child-side half of each unchecked, exactly the code that matters most.
#
# Only src/ is scanned: headers carry declarations, not bodies, and there is
# nothing in a declaration that can allocate.
#
# Exit code: 0 when clean, 1 when any violation is found.
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SOURCE_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${SOURCE_DIR}" || exit 1

violations=0

# Kept as one extended-regex alternation so a single awk pass tests them all.
# Note the [(] character classes: awk's -v assignment processes backslash
# escapes before the value reaches the program, so a \\( here would arrive as a
# bare ( and make the regex invalid. A character class needs no escape.
BANNED='MC_LOG_(TRACE|DEBUG|INFO|WARN|ERROR|AT)|std::string|std::vector|[^_a-zA-Z]new[[:space:]]|malloc[(]|calloc[(]|realloc[(]|strdup[(]|snprintf[(]|[^_a-zA-Z]throw[[:space:]]'

while IFS= read -r file; do
  # awk tracks brace depth so it knows where each body ends. Lines inside a
  # step_* body are tested; everything else in the same file - including its
  # parent-side functions - is ignored.
  awk -v file="$file" -v banned="$BANNED" '
    # A definition opens a body; a declaration ends in ";". Only the former is
    # scanned - entering on a declaration would never find a closing brace and
    # would flag the rest of the file.
    /^ChildStatus step_[a-z_]*\(/ && !/;[[:space:]]*$/ {
      in_step = 1
      depth = 0
      name = $0
      sub(/\(.*/, "", name)
      sub(/^ChildStatus /, "", name)
    }
    in_step {
      line = $0
      opens = gsub(/{/, "{", line)
      line = $0
      closes = gsub(/}/, "}", line)
      depth += opens - closes

      stripped = $0
      sub(/^[[:space:]]*/, "", stripped)
      is_comment = (substr(stripped, 1, 2) == "//")

      # Comments may legitimately mention std::string while explaining why it
      # is banned, so they are exempt; the signature line is skipped too.
      if (!is_comment && $0 !~ /^ChildStatus step_/) {
        if ($0 ~ banned) {
          printf "%s:%d: in %s(): %s\n", file, NR, name, stripped
          found = 1
        }
      }

      if (depth <= 0 && opens + closes > 0) {
        in_step = 0
      }
    }
    END { exit found ? 1 : 0 }
  ' "$file" || violations=1
done < <(find src -name '*.cpp' | sort)

if [ "$violations" -ne 0 ]; then
  cat >&2 <<'MSG'

check-child-purity.sh: FAILED

The lines above are inside functions that run between clone() and execve().
Allocating there can deadlock the container process forever on a malloc lock
inherited from a thread that no longer exists - a hang with no diagnostic.

Use stack buffers and raw syscalls. For logging use MC_CLOG / MC_CLOG_N, which
do a single write(2) of a literal. If a value genuinely must be computed with
allocation, compute it in the PARENT before clone() and pass it through
ChildContext - that is what the arena in container.h is for.
MSG
  exit 1
fi

echo "check-child-purity.sh: PASS (no allocation in any step_* body)"
