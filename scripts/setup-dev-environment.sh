#!/usr/bin/env bash
# Provision a MiniContainer development environment on Ubuntu 22.04/24.04.
#
# Run this INSIDE Linux. If your host is Windows, first create the distro from
# PowerShell (see docs/getting-started.md):
#
#   $env:WSL_UTF8=1
#   wsl --install -d Ubuntu-24.04 --no-launch
#   wsl -d Ubuntu-24.04 -u root
#
# --no-launch matters: without it the first run stops at an interactive
# username/password prompt. Entering with -u root then avoids sudo entirely.
set -euo pipefail

info() { echo "==> $*"; }
warn() { echo "warning: $*" >&2; }

[ "$(id -u)" -eq 0 ] || { echo "run as root (wsl -d Ubuntu-24.04 -u root)" >&2; exit 1; }

if [ -r /etc/os-release ]; then . /etc/os-release; info "host: ${PRETTY_NAME:-unknown}"; fi
info "kernel: $(uname -r)"

info "installing packages"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y -qq --no-install-recommends \
  build-essential cmake ninja-build git pkg-config \
  libcap-dev libseccomp-dev libgtest-dev libgmock-dev \
  iproute2 iptables nftables uidmap \
  busybox-static debootstrap \
  curl ca-certificates jq python3 bc file \
  clang-format clang-tidy gdb strace

info "versions"
printf '  g++         %s\n' "$(g++ -dumpversion)"
printf '  cmake       %s\n' "$(cmake --version | head -1 | awk '{print $3}')"
printf '  ninja       %s\n' "$(ninja --version)"
printf '  libseccomp  %s\n' "$(pkg-config --modversion libseccomp 2>/dev/null || echo absent)"
printf '  libcap      %s\n' "$(pkg-config --modversion libcap 2>/dev/null || echo absent)"
printf '  iptables    %s\n' "$(iptables -V 2>/dev/null || echo absent)"

# g++ must be >= 10 for the C++20 features we rely on.
gccmaj="$(g++ -dumpversion | cut -d. -f1)"
[ "$gccmaj" -ge 10 ] || warn "g++ $gccmaj is too old; C++20 support needs >= 10"

info "runtime directories"
mkdir -p /var/lib/minicontainer/images
chmod 700 /var/lib/minicontainer
echo "  /var/lib/minicontainer (fstype: $(findmnt -no FSTYPE -T /var/lib/minicontainer 2>/dev/null || echo unknown))"

# cgroup v2 controllers must be delegated to child cgroups, or our cgroup
# directories are created with NO memory.max/cpu.max/pids.max files at all -
# silently, with no error. Probe and fix rather than assume.
info "cgroup v2 delegation"
if [ "$(stat -fc %T /sys/fs/cgroup 2>/dev/null)" = "cgroup2fs" ] || \
   awk '$5=="/sys/fs/cgroup" && $9=="cgroup2"{f=1} END{exit !f}' /proc/self/mountinfo; then
  have="$(cat /sys/fs/cgroup/cgroup.subtree_control 2>/dev/null || echo)"
  echo "  controllers:     $(cat /sys/fs/cgroup/cgroup.controllers 2>/dev/null)"
  echo "  subtree_control: ${have:-<empty>}"
  for c in cpu memory pids; do
    case " $have " in
      *" $c "*) ;;
      *) if echo "+$c" > /sys/fs/cgroup/cgroup.subtree_control 2>/dev/null; then
           echo "  enabled +$c"
         else
           warn "could not enable '$c' (EBUSY here means the cgroup directly contains processes)"
         fi ;;
    esac
  done
else
  warn "/sys/fs/cgroup is not cgroup2. On WSL add 'systemd=true' under [boot] in /etc/wsl.conf, then 'wsl --shutdown'."
fi

info "building a busybox rootfs"
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
bash "$here/create-rootfs.sh" /var/lib/minicontainer/images/busybox >/dev/null && \
  echo "  /var/lib/minicontainer/images/busybox"

echo
info "environment ready"
cat <<NEXT

Next:
  bash scripts/check-environment.sh          # verify kernel features
  bash scripts/wsl-build.sh                  # configure + build + test

Note: keep the build tree OFF /mnt/c. drvfs is 9p and cannot represent Linux
mode bits or device nodes, and compiles there are several times slower.
NEXT
