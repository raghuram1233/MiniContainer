#!/usr/bin/env bash
# Reap resources left behind by a crashed MiniContainer run.
#
# SAFETY CONTRACT
# This script is deliberately narrow. It only ever touches resources that
# MiniContainer itself creates, identified by fixed naming conventions:
#
#   cgroups     /sys/fs/cgroup/minicontainer/*
#   state       /var/lib/minicontainer/<id>/
#   interfaces  names beginning "mc-"
#   mounts      mount points under /var/lib/minicontainer/
#
# It will never unmount an arbitrary path, delete a cgroup it does not own, or
# remove a network interface it did not create. A cleanup tool that guesses is
# far more dangerous than the leak it is fixing.
set -uo pipefail

DRY_RUN=0
FORCE=0
STATE_ROOT="${MINICONTAINER_ROOT:-/var/lib/minicontainer}"
CGROUP_ROOT="${MINICONTAINER_CGROUP_ROOT:-/sys/fs/cgroup}"
CGROUP_SCOPE="minicontainer"
IFACE_PREFIX="mc-"

usage() {
  cat <<USAGE
usage: cleanup.sh [--dry-run] [--force]

  --dry-run   show what would be removed, change nothing
  --force     also kill still-running container processes
USAGE
  exit 0
}
for a in "$@"; do
  case "$a" in
    --dry-run) DRY_RUN=1 ;;
    --force)   FORCE=1 ;;
    -h|--help) usage ;;
    *) echo "unknown argument: $a" >&2; exit 2 ;;
  esac
done

[ "$(id -u)" -eq 0 ] || { echo "cleanup.sh must run as root" >&2; exit 1; }

run() {
  if [ "$DRY_RUN" -eq 1 ]; then echo "  [dry-run] $*"; else "$@" 2>/dev/null; fi
}
info() { echo "==> $*"; }

# --- 1. processes -----------------------------------------------------------
# Read pids from the cgroups we own, so we never kill by name matching.
info "container processes"
found_procs=0
if [ -d "$CGROUP_ROOT/$CGROUP_SCOPE" ]; then
  while IFS= read -r procfile; do
    [ -f "$procfile" ] || continue
    while IFS= read -r pid; do
      [ -n "$pid" ] || continue
      found_procs=1
      cmd="$(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null | cut -c1-60)"
      echo "  pid $pid  ($cmd)  in $(dirname "${procfile#"$CGROUP_ROOT/"}")"
      if [ "$FORCE" -eq 1 ]; then run kill -KILL "$pid"; fi
    done < "$procfile"
  done < <(find "$CGROUP_ROOT/$CGROUP_SCOPE" -name cgroup.procs 2>/dev/null)
fi
[ "$found_procs" -eq 1 ] || echo "  none"
[ "$found_procs" -eq 1 ] && [ "$FORCE" -eq 0 ] && echo "  (use --force to kill)"

# --- 2. mounts --------------------------------------------------------------
# Reverse order: deepest mount first, or the parent unmount fails with EBUSY.
info "leaked mounts under $STATE_ROOT"
found_mounts=0
while IFS= read -r mp; do
  [ -n "$mp" ] || continue
  found_mounts=1
  echo "  $mp"
  run umount -l "$mp"
done < <(awk -v root="$STATE_ROOT" '$5 ~ "^"root {print $5}' /proc/self/mountinfo 2>/dev/null | sort -r)
[ "$found_mounts" -eq 1 ] || echo "  none"

# --- 3. cgroups -------------------------------------------------------------
# rmdir only. A cgroup directory cannot be rm -rf'd, and rmdir fails with EBUSY
# while any process remains inside - which is the correct, safe behaviour.
info "cgroups under $CGROUP_ROOT/$CGROUP_SCOPE"
found_cg=0
if [ -d "$CGROUP_ROOT/$CGROUP_SCOPE" ]; then
  while IFS= read -r cg; do
    [ "$cg" = "$CGROUP_ROOT/$CGROUP_SCOPE" ] && continue
    found_cg=1
    echo "  ${cg#"$CGROUP_ROOT/"}"
    run rmdir "$cg"
  done < <(find "$CGROUP_ROOT/$CGROUP_SCOPE" -mindepth 1 -type d 2>/dev/null | sort -r)
  run rmdir "$CGROUP_ROOT/$CGROUP_SCOPE"
fi
[ "$found_cg" -eq 1 ] || echo "  none"

# --- 4. network interfaces --------------------------------------------------
# Deleting one end of a veth pair removes both, so peers need no separate pass.
info "interfaces named ${IFACE_PREFIX}*"
found_if=0
while IFS= read -r ifn; do
  [ -n "$ifn" ] || continue
  found_if=1
  echo "  $ifn"
  run ip link delete "$ifn"
done < <(ip -o link show 2>/dev/null | awk -F': ' '{print $2}' | cut -d@ -f1 | grep "^${IFACE_PREFIX}" || true)
[ "$found_if" -eq 1 ] || echo "  none"

# --- 5. stale state directories --------------------------------------------
# Only directories whose recorded pid is dead. A live container is left alone.
info "stale state directories in $STATE_ROOT"
found_state=0
if [ -d "$STATE_ROOT" ]; then
  for d in "$STATE_ROOT"/*/; do
    [ -d "$d" ] || continue
    case "$d" in "$STATE_ROOT"/images/) continue ;; esac
    pidfile="$d/pid"
    if [ -f "$pidfile" ]; then
      pid="$(cat "$pidfile" 2>/dev/null)"
      if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
        echo "  skip $(basename "$d") (pid $pid still alive)"
        continue
      fi
    fi
    found_state=1
    echo "  $(basename "$d")"
    run rm -rf "$d"
  done
fi
[ "$found_state" -eq 1 ] || echo "  none"

echo
if [ "$DRY_RUN" -eq 1 ]; then
  echo "dry run - nothing was changed. Re-run without --dry-run to apply."
else
  echo "cleanup complete."
fi
