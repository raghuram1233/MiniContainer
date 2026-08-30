#!/usr/bin/env bash
# check-environment.sh - probe this host for everything MiniContainer needs,
# print a PASS/WARN/FAIL table, and exit non-zero only if something FAILed.
#
# This script gates every later workstream: namespaces, cgroups, networking,
# and security all depend on kernel/host features that vary across
# "Linux-shaped" environments (native Ubuntu, WSL2, docker-desktop's own
# distro, CI runners...). It PROBES, it never ASSUMES - e.g. whether
# cgroup.subtree_control already has controllers enabled differs between the
# Ubuntu-24.04 WSL distro (systemd running, already enabled) and the
# docker-desktop distro (empty), even though both present as "cgroup v2".
#
# It creates nothing that outlives the script: every resource (net links,
# temp dirs, mount namespaces) is removed/unshared before exit, and it never
# writes to a live kernel knob (e.g. cgroup.subtree_control) - it only
# reports what *would* need to change and how.
#
# Exit code: 0 unless at least one check FAILed.

set -u
umask 022

# ---------------------------------------------------------------------------
# Result table plumbing
# ---------------------------------------------------------------------------
RESULTS=()   # each entry: "STATUS<TAB>name<TAB>detail<TAB>hint"
FAIL_COUNT=0
WARN_COUNT=0

record() {
  # record STATUS name detail hint
  local status="$1" name="$2" detail="$3" hint="${4:-}"
  RESULTS+=("${status}"$'\t'"${name}"$'\t'"${detail}"$'\t'"${hint}")
  case "${status}" in
    FAIL) FAIL_COUNT=$((FAIL_COUNT + 1)) ;;
    WARN) WARN_COUNT=$((WARN_COUNT + 1)) ;;
  esac
}

CLEANUP_CMDS=()
on_exit() {
  local i
  for ((i = ${#CLEANUP_CMDS[@]} - 1; i >= 0; i--)); do
    eval "${CLEANUP_CMDS[i]}" >/dev/null 2>&1 || true
  done
}
trap on_exit EXIT

need_root_warned=0
require_root_for() {
  if [ "$(id -u)" -ne 0 ] && [ "${need_root_warned}" -eq 0 ]; then
    need_root_warned=1
  fi
  [ "$(id -u)" -eq 0 ]
}

# ---------------------------------------------------------------------------
# 1. cgroup v2 unified hierarchy
# ---------------------------------------------------------------------------
check_cgroup_v2() {
  local line fstype
  line="$(awk '$5=="/sys/fs/cgroup"{print; exit}' /proc/self/mountinfo)"
  if [ -z "${line}" ]; then
    record FAIL "cgroup v2 unified mount" \
      "/sys/fs/cgroup is not a mountpoint" \
      "mount -t cgroup2 none /sys/fs/cgroup, or boot with systemd.unified_cgroup_hierarchy=1"
    return
  fi
  fstype="$(printf '%s\n' "${line}" | awk -F' - ' '{print $2}' | awk '{print $1}')"
  if [ "${fstype}" = "cgroup2" ]; then
    record PASS "cgroup v2 unified mount" "/sys/fs/cgroup is cgroup2" ""
  else
    record FAIL "cgroup v2 unified mount" \
      "/sys/fs/cgroup is '${fstype}', not cgroup2 (likely cgroup v1 hybrid/legacy)" \
      "Boot with cgroup_no_v1=all or systemd.unified_cgroup_hierarchy=1"
  fi
}

# ---------------------------------------------------------------------------
# 2. Root cgroup.controllers / cgroup.subtree_control contain cpu,memory,pids
# ---------------------------------------------------------------------------
check_cgroup_controllers() {
  local root="/sys/fs/cgroup"
  local need="cpu memory pids"
  local have_avail have_sub missing_avail missing_sub c

  if [ ! -r "${root}/cgroup.controllers" ]; then
    record FAIL "cgroup available controllers" \
      "${root}/cgroup.controllers not readable" \
      "Confirm cgroup2 is mounted at ${root} (see previous check)"
    return
  fi
  have_avail="$(cat "${root}/cgroup.controllers" 2>/dev/null)"
  missing_avail=""
  for c in ${need}; do
    case " ${have_avail} " in
      *" ${c} "*) ;;
      *) missing_avail="${missing_avail} ${c}" ;;
    esac
  done
  if [ -z "${missing_avail}" ]; then
    record PASS "cgroup available controllers" "cgroup.controllers = '${have_avail}'" ""
  else
    record FAIL "cgroup available controllers" \
      "missing:${missing_avail} (have: '${have_avail}')" \
      "Kernel/host does not expose these controllers at the root cgroup; check kernel config and any 'cgroup_enable=' boot args"
  fi

  if [ ! -r "${root}/cgroup.subtree_control" ]; then
    record WARN "cgroup subtree_control" \
      "${root}/cgroup.subtree_control not readable" ""
    return
  fi
  have_sub="$(cat "${root}/cgroup.subtree_control" 2>/dev/null)"
  missing_sub=""
  for c in ${need}; do
    case " ${have_sub} " in
      *" ${c} "*) ;;
      *) missing_sub="${missing_sub} ${c}" ;;
    esac
  done
  if [ -z "${missing_sub}" ]; then
    record PASS "cgroup subtree_control" "cgroup.subtree_control = '${have_sub}'" ""
  else
    # Measured fact: on the Ubuntu-24.04 WSL distro (systemd running) this is
    # already "cpu memory pids"; on the docker-desktop distro it is empty.
    # Never write to it here - only report the fix.
    record WARN "cgroup subtree_control" \
      "missing:${missing_sub} (have: '${have_sub}')" \
      "echo '+cpu +memory +pids' > ${root}/cgroup.subtree_control (as root; only affects descendants, not the root cgroup's own processes)"
  fi
}

# ---------------------------------------------------------------------------
# 3. User namespaces
# ---------------------------------------------------------------------------
check_userns() {
  local max_userns apparmor_knob
  if unshare -Ur true 2>/dev/null; then
    record PASS "user namespaces (unshare -Ur)" "unshare -Ur true succeeded" ""
  else
    record FAIL "user namespaces (unshare -Ur)" "unshare -Ur true failed" \
      "Check /proc/sys/user/max_user_namespaces > 0 and that no LSM (AppArmor/SELinux) is blocking unprivileged userns creation"
  fi

  if [ -r /proc/sys/user/max_user_namespaces ]; then
    max_userns="$(cat /proc/sys/user/max_user_namespaces)"
    if [ "${max_userns}" = "0" ]; then
      record FAIL "max_user_namespaces" "0 (user namespaces disabled)" \
        "sysctl -w user.max_user_namespaces=<N>, e.g. 15000, then persist in /etc/sysctl.d/"
    else
      record PASS "max_user_namespaces" "${max_userns}" ""
    fi
  else
    record WARN "max_user_namespaces" "/proc/sys/user/max_user_namespaces missing" \
      "Kernel may be built without CONFIG_USER_NS"
  fi

  # Portability trap: this sysctl exists on native Ubuntu 24.04's hardened
  # kernel but does NOT exist on the WSL2 kernel. Both are "Linux 24.04" -
  # do not assume either way.
  apparmor_knob="/proc/sys/kernel/apparmor_restrict_unprivileged_userns"
  if [ -e "${apparmor_knob}" ]; then
    record WARN "apparmor_restrict_unprivileged_userns" \
      "present, value=$(cat "${apparmor_knob}" 2>/dev/null || echo '?') - this host enforces Ubuntu's AppArmor userns restriction" \
      "If unprivileged userns creation fails for non-root users, either run as root, add an AppArmor profile allowing userns_create, or: sysctl -w kernel.apparmor_restrict_unprivileged_userns=0"
  else
    record PASS "apparmor_restrict_unprivileged_userns" \
      "absent (expected on the WSL2 kernel; would be present on native Ubuntu 24.04 - portability trap, not a bug)" ""
  fi
}

# ---------------------------------------------------------------------------
# 4. pivot_root inside unshare -m --propagation private
# ---------------------------------------------------------------------------
check_pivot_root() {
  local fstype base
  fstype="$(findmnt -no FSTYPE -T /tmp 2>/dev/null || echo unknown)"
  case "${fstype}" in
    9p|drvfs)
      record WARN "pivot_root" "skipped: /tmp is on ${fstype}, not a real Linux filesystem" \
        "Run this script with TMPDIR pointing at ext4 (e.g. /root, /var/tmp on WSL's own disk)"
      return
      ;;
  esac
  if [ "$(id -u)" -ne 0 ]; then
    record WARN "pivot_root" "skipped: requires root" "Run as root"
    return
  fi
  if ! command -v unshare >/dev/null 2>&1; then
    record WARN "pivot_root" "skipped: unshare(1) not found" "apt install util-linux"
    return
  fi

  base="$(mktemp -d "${TMPDIR:-/tmp}/mc-check-pivot.XXXXXX")" || {
    record FAIL "pivot_root" "mktemp failed" ""
    return
  }
  CLEANUP_CMDS+=("rm -rf '${base}'")

  # After pivot_root, the process root is the (empty) bind-mounted newroot -
  # there is no /usr/bin in it, so no external binary (not even umount) can
  # be exec'd there. Use only shell builtins after pivot_root succeeds; the
  # private mount namespace (and its old-root mount) is torn down for free
  # by the kernel when this bash -c subshell exits - no explicit umount
  # needed, and nothing leaks into the host's mount table.
  if unshare -m --propagation private -- bash -c '
      set -e
      newroot="'"${base}"'/newroot"
      mkdir -p "${newroot}"
      mount --bind "${newroot}" "${newroot}"
      cd "${newroot}"
      mkdir -p oldroot
      pivot_root . oldroot
      cd /
      exit 0
    ' 2>/tmp/mc-check-pivot-err.$$; then
    record PASS "pivot_root (in unshare -m --propagation private)" "pivot_root succeeded" ""
  else
    record FAIL "pivot_root (in unshare -m --propagation private)" \
      "$(tail -n1 /tmp/mc-check-pivot-err.$$ 2>/dev/null)" \
      "Requires CONFIG_MNT_NS and a kernel that allows pivot_root in a non-init mount namespace; check dmesg for LSM denials"
  fi
  rm -f /tmp/mc-check-pivot-err.$$
}

# ---------------------------------------------------------------------------
# 5. mknod (must run on ext4, never on /mnt/c)
# ---------------------------------------------------------------------------
check_mknod() {
  local fstype target
  fstype="$(findmnt -no FSTYPE -T "${TMPDIR:-/tmp}" 2>/dev/null || echo unknown)"
  case "${fstype}" in
    9p|drvfs)
      record WARN "mknod" "skipped: ${TMPDIR:-/tmp} is on ${fstype}" \
        "Point TMPDIR at a native ext4 path, e.g. /root or /var/tmp"
      return
      ;;
  esac
  target="$(mktemp -u "${TMPDIR:-/tmp}/mc-check-mknod.XXXXXX")"
  if mknod "${target}" c 1 3 2>/tmp/mc-check-mknod-err.$$; then
    rm -f "${target}"
    record PASS "mknod (char device on ${fstype})" "mknod succeeded" ""
  else
    record FAIL "mknod (char device on ${fstype})" \
      "$(cat /tmp/mc-check-mknod-err.$$ 2>/dev/null)" \
      "Needs CAP_MKNOD and a filesystem that supports device nodes (ext4 does; 9p/drvfs/some overlay configs do not)"
  fi
  rm -f /tmp/mc-check-mknod-err.$$
}

# ---------------------------------------------------------------------------
# 6. seccomp
# ---------------------------------------------------------------------------
check_seccomp() {
  if [ -r /proc/config.gz ]; then
    if zcat /proc/config.gz 2>/dev/null | grep -q '^CONFIG_SECCOMP_FILTER=y'; then
      record PASS "CONFIG_SECCOMP_FILTER" "enabled (from /proc/config.gz)" ""
    else
      record FAIL "CONFIG_SECCOMP_FILTER" "not enabled in running kernel" \
        "Rebuild/choose a kernel with CONFIG_SECCOMP_FILTER=y"
    fi
  else
    record WARN "CONFIG_SECCOMP_FILTER" "/proc/config.gz not readable; cannot confirm from kernel config" \
      "Check /boot/config-\$(uname -r) instead, or enable CONFIG_IKCONFIG_PROC"
  fi

  if pkg-config --exists libseccomp 2>/dev/null; then
    record PASS "libseccomp (pkg-config)" "$(pkg-config --modversion libseccomp)" ""
  elif ldconfig -p 2>/dev/null | grep -q libseccomp; then
    record WARN "libseccomp (pkg-config)" "library present but no pkg-config .pc file found" \
      "apt install libseccomp-dev"
  else
    record FAIL "libseccomp" "not found" "apt install libseccomp-dev"
  fi
}

# ---------------------------------------------------------------------------
# 7. veth + bridge creation
# ---------------------------------------------------------------------------
check_veth_bridge() {
  if [ "$(id -u)" -ne 0 ]; then
    record WARN "veth pair creation" "skipped: requires root/CAP_NET_ADMIN" "Run as root"
    record WARN "bridge creation" "skipped: requires root/CAP_NET_ADMIN" "Run as root"
    return
  fi
  if ! command -v ip >/dev/null 2>&1; then
    record FAIL "veth pair creation" "iproute2 'ip' not found" "apt install iproute2"
    record FAIL "bridge creation" "iproute2 'ip' not found" "apt install iproute2"
    return
  fi

  local a="mc-chk-veth0" b="mc-chk-veth1"
  if ip link add "${a}" type veth peer name "${b}" 2>/tmp/mc-check-veth-err.$$; then
    ip link delete "${a}" >/dev/null 2>&1 || true
    record PASS "veth pair creation" "ip link add/delete veth succeeded" ""
  else
    record FAIL "veth pair creation" "$(cat /tmp/mc-check-veth-err.$$ 2>/dev/null)" \
      "Needs CAP_NET_ADMIN and the veth kernel module (usually built-in)"
  fi
  rm -f /tmp/mc-check-veth-err.$$

  local br="mc-chk-br0"
  if ip link add "${br}" type bridge 2>/tmp/mc-check-bridge-err.$$; then
    ip link delete "${br}" >/dev/null 2>&1 || true
    record PASS "bridge creation" "ip link add/delete bridge succeeded" ""
  else
    record FAIL "bridge creation" "$(cat /tmp/mc-check-bridge-err.$$ 2>/dev/null)" \
      "Needs CAP_NET_ADMIN and the bridge kernel module: modprobe bridge"
  fi
  rm -f /tmp/mc-check-bridge-err.$$
}

# ---------------------------------------------------------------------------
# 8. ip_forward + iptables backend
# ---------------------------------------------------------------------------
check_iptables() {
  local fwd
  if [ -r /proc/sys/net/ipv4/ip_forward ]; then
    fwd="$(cat /proc/sys/net/ipv4/ip_forward)"
    if [ "${fwd}" = "1" ]; then
      record PASS "net.ipv4.ip_forward" "1" ""
    else
      record WARN "net.ipv4.ip_forward" "${fwd} (disabled)" \
        "sysctl -w net.ipv4.ip_forward=1 (needed for NAT/bridge networking mode)"
    fi
  else
    record WARN "net.ipv4.ip_forward" "/proc/sys/net/ipv4/ip_forward missing" ""
  fi

  if ! command -v iptables >/dev/null 2>&1; then
    record FAIL "iptables" "not found" "apt install iptables"
    return
  fi
  local ver backend
  ver="$(iptables --version 2>/dev/null)"
  case "${ver}" in
    *nf_tables*) backend="nf_tables" ;;
    *legacy*) backend="legacy" ;;
    *) backend="unknown" ;;
  esac
  record PASS "iptables" "${ver} (backend: ${backend})" \
    "$([ "${backend}" = "legacy" ] && echo 'legacy backend detected; MiniContainer assumes nf_tables semantics on modern hosts - verify rule ordering if you see NAT problems')"
}

# ---------------------------------------------------------------------------
# 9. Filesystem type warnings (9p/drvfs under state/rootfs dirs)
# ---------------------------------------------------------------------------
check_fs_backing() {
  local path="${MINICONTAINER_ROOT:-/var/lib/minicontainer}"
  local fstype
  fstype="$(findmnt -no FSTYPE -T "${path}" 2>/dev/null || echo unknown)"
  case "${fstype}" in
    9p|drvfs)
      record WARN "state dir filesystem (${path})" \
        "backed by ${fstype} (a Windows-drive mount)" \
        "Set MINICONTAINER_ROOT to a path on native ext4, e.g. /var/lib/minicontainer on the WSL root disk, not /mnt/c/..."
      ;;
    unknown)
      record WARN "state dir filesystem (${path})" "could not determine filesystem type" ""
      ;;
    *)
      record PASS "state dir filesystem (${path})" "${fstype}" ""
      ;;
  esac

  # The repo itself is expected to live on drvfs (C:\...) in this project's
  # environment; that's fine for source, just never for the build tree or
  # runtime state. Report it as informational, not a WARN.
  local src_fstype
  src_fstype="$(findmnt -no FSTYPE -T "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)" 2>/dev/null || echo unknown)"
  record PASS "source tree filesystem" \
    "${src_fstype} (expected to be 9p/drvfs on this project's Windows-hosted layout; build dir must NOT be here - use ~/mc-build)" ""
}

# ---------------------------------------------------------------------------
# Run all checks
# ---------------------------------------------------------------------------
check_cgroup_v2
check_cgroup_controllers
check_userns
check_pivot_root
check_mknod
check_seccomp
check_veth_bridge
check_iptables
check_fs_backing

# ---------------------------------------------------------------------------
# Print the table
# ---------------------------------------------------------------------------
printf '\n%-6s %-45s %s\n' "STATUS" "CHECK" "DETAIL"
printf '%s\n' "--------------------------------------------------------------------------------"
for entry in "${RESULTS[@]}"; do
  IFS=$'\t' read -r status name detail hint <<<"${entry}"
  printf '%-6s %-45s %s\n' "${status}" "${name}" "${detail}"
  if [ -n "${hint}" ]; then
    printf '       %-45s -> %s\n' "" "${hint}"
  fi
done
printf '%s\n' "--------------------------------------------------------------------------------"
printf 'Summary: %d check(s), %d WARN, %d FAIL\n\n' "${#RESULTS[@]}" "${WARN_COUNT}" "${FAIL_COUNT}"

if [ "${FAIL_COUNT}" -gt 0 ]; then
  echo "check-environment.sh: FAIL - ${FAIL_COUNT} check(s) failed; see hints above." >&2
  exit 1
fi

echo "check-environment.sh: PASS (with ${WARN_COUNT} warning(s))."
exit 0
