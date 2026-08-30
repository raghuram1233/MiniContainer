#!/usr/bin/env bash
# Build a minimal container root filesystem for MiniContainer.
#
# WHY THIS SCRIPT EXISTS
# A container needs a root filesystem containing the entrypoint binary and every
# shared library it needs. "It works on the host" is not enough: after
# pivot_root() the host's /lib is gone, so a dynamically linked binary that
# cannot find its interpreter fails with a bare ENOENT that looks like the
# binary itself is missing. Using a STATIC busybox sidesteps that entirely,
# which is why it is the default here.
#
# CRITICAL: the rootfs must live on ext4, never on /mnt/c. drvfs is 9p and
# cannot store device nodes or correct mode bits, so mknod fails and every file
# reports mode 0777.
set -euo pipefail

DEST="${1:-/var/lib/minicontainer/images/busybox}"
METHOD="${METHOD:-busybox}"   # busybox | docker | debootstrap

die() { echo "error: $*" >&2; exit 1; }
info() { echo "==> $*"; }

# --- refuse to build on a filesystem that cannot represent a rootfs ----------
parent="$DEST"
while [ ! -d "$parent" ]; do parent="$(dirname "$parent")"; done
fstype="$(findmnt -no FSTYPE -T "$parent" 2>/dev/null || echo unknown)"
case "$fstype" in
  9p|drvfs|cifs|vboxsf)
    die "$DEST is on '$fstype'. A rootfs needs a real Linux filesystem
       (device nodes, mode bits, symlinks). Use a path under /var/lib or \$HOME." ;;
esac
info "target $DEST (fstype: $fstype)"

mkdir -p "$DEST"
cd "$DEST"

# Standard FHS skeleton. proc/sys/dev are mount points; the runtime mounts them.
mkdir -p bin sbin etc proc sys dev dev/pts dev/shm tmp var/log root home usr/bin usr/sbin lib lib64
chmod 1777 tmp dev/shm

case "$METHOD" in
  busybox)
    BB="$(command -v busybox || true)"
    [ -n "$BB" ] || die "busybox not found. apt-get install -y busybox-static"
    if ldd "$BB" >/dev/null 2>&1; then
      echo "warning: $BB is dynamically linked; prefer busybox-static" >&2
    fi
    info "installing $BB"
    cp "$BB" bin/busybox
    chmod 755 bin/busybox
    # Applet symlinks. Every one of these becomes a working command inside the
    # container without adding a single extra byte.
    for applet in sh ls cat echo ps mount umount hostname id sleep ping ip \
                  mkdir rm cp mv grep sed awk env printenv true false pwd \
                  chmod chown ln touch head tail wc date df du kill top free \
                  dmesg uname whoami stat readlink find xargs sort uniq tr yes; do
      ln -sf busybox "bin/$applet"
    done
    ;;
  docker)
    command -v docker >/dev/null || die "docker not found"
    info "exporting a container filesystem via docker (baseline/rootfs source only)"
    cid="$(docker create busybox:latest /bin/sh)"
    docker export "$cid" | tar -x -C "$DEST"
    docker rm -f "$cid" >/dev/null
    ;;
  debootstrap)
    command -v debootstrap >/dev/null || die "debootstrap not found"
    info "bootstrapping Debian stable (this takes several minutes)"
    debootstrap --variant=minbase stable "$DEST" http://deb.debian.org/debian
    ;;
  *) die "unknown METHOD '$METHOD' (busybox|docker|debootstrap)" ;;
esac

# --- minimal /etc so the container is not obviously broken ------------------
[ -f etc/passwd ] || printf 'root:x:0:0:root:/root:/bin/sh\nnobody:x:65534:65534:nobody:/:/bin/false\n' > etc/passwd
[ -f etc/group ]  || printf 'root:x:0:\nnogroup:x:65534:\n' > etc/group
[ -f etc/hosts ]  || printf '127.0.0.1 localhost\n::1 localhost\n' > etc/hosts
[ -f etc/resolv.conf ] || printf 'nameserver 1.1.1.1\nnameserver 8.8.8.8\n' > etc/resolv.conf

echo
info "verifying"
fail=0
[ -x bin/sh ] || { echo "  MISSING: /bin/sh"; fail=1; }
if [ -e bin/sh ]; then
  # A static binary has no interpreter; a dynamic one must have its libs present.
  if file -L bin/sh 2>/dev/null | grep -q "dynamically linked"; then
    echo "  /bin/sh is DYNAMIC - its libraries must exist inside the rootfs:"
    ldd bin/sh 2>/dev/null | sed 's/^/    /'
  else
    echo "  /bin/sh is static - no interpreter needed inside the container"
  fi
fi
for d in proc sys dev tmp etc; do
  [ -d "$d" ] || { echo "  MISSING dir: /$d"; fail=1; }
done
echo "  size: $(du -sh "$DEST" 2>/dev/null | cut -f1)"
echo "  entries: $(find "$DEST" -maxdepth 1 | wc -l)"
[ "$fail" -eq 0 ] || die "rootfs verification failed"

echo
info "rootfs ready: $DEST"
echo "    minicontainer run --rootfs $DEST /bin/sh"
