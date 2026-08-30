# Filesystem Isolation

Status: **Planned.** No filesystem module exists yet in `src/filesystem/`.
The relevant `Op` enumerators in `errors.h` (`MakeRootPrivate`, `BindRootfs`,
`MountProc`, `MountSys`, `MountDev`, `CreateDeviceNode`, `MountDevPts`,
`MountTmp`, `PivotRoot`, `UmountOldRoot`, `RemountReadonly`) define the
intended child-side step sequence. This document explains the mount
namespace mechanics that sequence depends on getting right, in order.

## The problem it solves

A container needs its own root filesystem — a different `/bin`, `/etc`,
`/lib` than the host's — without literally copying the host's mount table
apart, and without letting a mount or unmount performed inside the
container leak out to the host or to other containers.

## The primitive: mount namespaces + propagation

`CLONE_NEWNS` (see `docs/namespaces.md`) gives a process its own list of
mount points. That alone is not sufficient, because mounts also have a
**propagation type**, independent of which namespace they're in:

- **shared**: mount/unmount events propagate to and from a peer group of
  mounts in other namespaces — this is the *default* on most modern
  distros, because systemd sets `/` to shared propagation at boot so that,
  e.g., a USB drive mounted in one namespace shows up in others that share
  it (useful for things like `systemd-nspawn` but exactly wrong for a
  container that wants to be isolated).
- **private**: no propagation either direction. What a container's mount
  namespace needs.
- **slave**: receives propagation from the peer group but doesn't send any
  back — receives host mount events without leaking its own.
- **unbindable**: cannot be bind-mounted at all.

**Why `MS_REC|MS_PRIVATE` must come first.** If the container's new mount
namespace inherits `/` as *shared* (the common default), every mount the
container performs inside its own namespace — bind-mounting the rootfs,
mounting `/proc`, `/dev/pts` — propagates straight back to the host's mount
table, and every host mount event propagates into the container. That is
the opposite of isolation, and it happens *silently*: nothing errors, mount
tables just quietly merge. The fix is the very first mount operation in
child setup (the `MakeRootPrivate` step):

```c
mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL);
```

`MS_REC` makes this recursive — it must apply to *every* mount currently
under `/`, not just the top-level entry, or a shared mount several levels
deep (a bind mount the host made, say) still leaks. This has to run before
any other mount operation in the child, which is why it is the very first
step in the `Op` sequence after entering the mount namespace.

## chroot vs pivot_root, and the double-chroot escape

`chroot(2)` changes a process's notion of `/` but does **not** change the
current working directory outside that root if the process already has an
open fd or cwd outside it, and critically: `chroot` does not detach the old
root from the mount tree at all. A process with `CAP_SYS_ADMIN` inside a
`chroot` jail can escape it with the classic **double-chroot trick**:

```c
mkdir("escape", 0755);
chroot("escape");        // now "rooted" one level below where we were
chdir("../../../../..")  // cwd predates the chroot; keep climbing with ..
chroot(".");              // re-root at the now-reachable real /
```

Because the working directory's dentry chain still leads back to the real
filesystem root (chroot never severed it, only changed the label `/`
refers to), repeated `..` from a stale cwd eventually reaches outside the
jail. This is why `chroot` was never designed as, and is not, a security
boundary — it predates containers by decades and was built for build
sandboxes and rescue environments, not for confining an adversarial
process.

`pivot_root(2)` is different in kind, not just tighter: it makes a *new*
filesystem the process's root **and moves the old root to a location
inside the new root**, in one atomic operation, working with the actual
mount tree rather than just a path label. The typical sequence:

```c
mount(new_root, new_root, NULL, MS_BIND, NULL);  // must itself be a mount point
mkdir(new_root_old, 0700);                        // e.g. new_root/oldroot
pivot_root(new_root, new_root_old);
chdir("/");
umount2("/oldroot", MNT_DETACH);
rmdir("/oldroot");
```

`pivot_root` requires `new_root` to already be a mount point (a plain
directory won't do — hence the self-bind-mount trick above when the rootfs
isn't already one) and it operates on the *whole mount tree*, so there is
no dentry left pointing at the true old root the way there is with
`chroot`. The old root is still mounted (at `/oldroot` in the example)
immediately after `pivot_root` — the next step, `UmountOldRoot`, detaches
it.

## Why `MNT_DETACH`

Unmounting the old root with `umount2(path, MNT_DETACH)` — a **lazy
unmount** — rather than a plain `umount2(path, 0)` matters because a plain
unmount can fail with `EBUSY` if anything still has the old root open (an
inherited fd, a library the dynamic linker mapped from it, a shell's cwd
that hasn't been changed yet). `MNT_DETACH` disconnects the mount from the
namespace's mount tree immediately — no new access can reach it through
that path — but defers the actual unmount until the last reference drops,
so setup does not have to race against every fd that might still be open
on the old root. This is the standard, correct way container runtimes
detach the old root and is why `UmountOldRoot` is a distinct, unconditional
step rather than something that's allowed to fail and be skipped.

## The rest of the mount sequence

The mounts happen **before** `pivot_root`, against `<rootfs>/proc`,
`<rootfs>/sys` and so on, while the old root is still reachable - then the
pivot happens once, at the end. That is the order frozen in `errors.h`'s
`MC_OP_LIST`, which documents the child-setup ops in execution order, and it
is what `src/container/steps.cpp` implements. It is also what runc does, and
it avoids the awkwardness of needing a working `/proc` in order to mount
`/proc`.

(An earlier draft of this document described the reverse order. The header is
the contract; this text was the thing that was wrong.)

The pseudo-filesystems the child populates are:

- `MountProc`: `mount("proc", "/proc", "proc", MS_NOSUID|MS_NODEV|MS_NOEXEC, NULL)`
  — gives the container its own `/proc`, scoped by the PID namespace it's
  in, so `/proc` inside only shows the container's own processes.
- `MountSys`: `/sys` — typically read-only inside an unprivileged container,
  since it exposes host hardware/kernel state that shouldn't be writable
  from inside.
- `MountDev`: a `tmpfs` at `/dev`, populated with the minimal device nodes
  the container needs (`CreateDeviceNode`: `null`, `zero`, `full`,
  `random`, `urandom`, `tty`) via `mknod(2)` rather than bind-mounting the
  host's `/dev` wholesale (which would leak every host device node).
- `MountDevPts`: `/dev/pts` for pseudo-terminal support (`tty`/`--interactive`
  containers).
- `MountTmp`: `/tmp` as its own `tmpfs`, isolated from the host's `/tmp`.
- `RemountReadonly`: if `SecurityConfig::readonly_rootfs` is set, remount
  the root `MS_RDONLY` as the *last* filesystem step, after everything that
  needed to write to set up the container has already run.

Extra bind mounts from `ContainerConfig::bind_mounts` (`"src:dst"` or
`"src:dst:ro"`) are layered in as part of this sequence too, each a
`MS_BIND` (optionally followed by a read-only remount, since `MS_BIND` and
`MS_RDONLY` cannot both be set in the same `mount()` call — a bind mount
must be remounted read-only in a second call).

## The drvfs/9p constraint

This project's development environment adds a real-world constraint worth
documenting precisely, because it's the kind of gotcha that costs hours if
undiagnosed: **the CMake build tree and any container rootfs or runtime
state must live on WSL's native ext4, never under `/mnt/c`.**

`/mnt/c` is drvfs, which bridges to the Windows filesystem over the 9p
protocol. 9p cannot represent Linux file mode bits (permission bits beyond
a coarse approximation), cannot hold device nodes at all, and its symlink
handling doesn't match native Linux semantics. Concretely: `mknod()` for
the `CreateDeviceNode` step above **fails outright** on a drvfs path — not
with a subtle permission issue, but because the underlying filesystem has
no representation for a device node. `pivot_root` also requires operating
on a real mount point with normal Linux mount semantics, which drvfs
paths, mounted via the `9p` client, do not reliably provide either.
Source code can live on `/mnt/c` (reading files doesn't stress these
limits); build output and anything MiniContainer creates at runtime cannot.

## Failure modes and common mistakes

- **`pivot_root` fails with `EINVAL`** — almost always means propagation
  wasn't set private first, or the new root isn't actually a mount point
  yet (forgot the self-bind-mount). See `docs/troubleshooting.md`.
- **Skipping `MS_REC`** on the initial private-propagation mount — the top
  level becomes private but nested mounts underneath stay shared, leaking
  anyway.
- **Bind-mounting `/dev` from the host wholesale** instead of populating a
  fresh `tmpfs` — exposes every host device node inside the container,
  including ones an unprivileged container process should never be able to
  open.
- **`mknod` `EPERM` inside a user namespace** — some device major/minor
  combinations remain restricted even with `CAP_MKNOD` mapped inside the
  namespace; see `docs/troubleshooting.md` for the specific symptom and
  workaround.
- **Building or running on `/mnt/c`** — silent-ish `mknod`/`pivot_root`
  failures that look like a bug in the runtime rather than an environment
  mismatch.

## How to debug it

```bash
findmnt                                  # the whole mount tree, tree-formatted
findmnt -N <pid>                         # a specific process's mount namespace view
cat /proc/<pid>/mountinfo                # raw mount table with propagation flags
nsenter -t <pid> -m findmnt              # inspect a running container's mounts
mount | grep <path>                      # is a path currently a mount point at all
```

`findmnt -o TARGET,PROPAGATION` is the fastest way to confirm a mount's
propagation type directly, rather than inferring it from behavior.

## Security implications

An isolated mount namespace with correct propagation stops mount/unmount
operations from crossing the container boundary, but it does **not**, by
itself, stop a process from reading host files it has a valid fd or bind
mount to already — mount namespace isolation is about the *mount table*,
not about revoking access to something already reachable. Combine with a
minimal rootfs (don't bind-mount more of the host than necessary),
read-only rootfs where possible, and the capability/seccomp layer
(`include/minicontainer/security.h`) which is what actually restricts *which* filesystem
syscalls a process may issue in the first place, regardless of what's
mounted.

## Likely interview questions

- *"Why isn't `chroot` enough for container isolation?"* — It only changes
  the path label `/` resolves to; it doesn't detach the old root from the
  mount tree, so a process with a stale cwd or sufficient privilege can
  climb back out via repeated `..` and re-`chroot` at the real root — the
  classic double-chroot escape.
- *"What does `pivot_root` do that `chroot` fundamentally cannot?"* — It
  operates on the mount tree itself, swapping which mount is root and
  relocating the old one, rather than just relabeling a path — there's no
  dangling reference back to the true root left over.
- *"Why must you set mount propagation to private before doing anything
  else?"* — Because the default (shared, inherited from a systemd-managed
  host `/`) means every subsequent mount operation would otherwise
  propagate to and from the host silently.
- *"Why `MNT_DETACH` instead of a plain unmount for the old root?"* — A
  plain unmount can fail with `EBUSY` if anything still references the old
  root; lazy unmount detaches it from the namespace immediately and
  finishes the actual teardown once references drop, without a busy-loop
  or race.
