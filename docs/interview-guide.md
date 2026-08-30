# Interview Guide: what happens when you run a container

This is the end-to-end walk through `minicontainer run --rootfs ./rootfs
/bin/sh`, syscall by syscall, with the reason for each step. It is the
document to read if you want to be able to *explain* containers rather than
recite that they are "namespaces plus cgroups".

Every claim here is implemented in this repository; the file is named so you
can go and read the code.

---

## The one-sentence version

A container is an ordinary Linux process that was created with several
`CLONE_NEW*` flags, had its root filesystem replaced, was placed in a cgroup,
had its privileges reduced, and then `execve`'d your program.

There is no "container" object in the kernel. That is the single most useful
thing to know.

---

## Phase 1 — the parent, before anything exists

`src/cli/parser.cpp` turns argv into a `ContainerConfig`. This is pure: no
syscalls beyond reading argv. That is what makes the whole CLI unit-testable
without root, and it is why the great majority of this project's tests need no
privileges at all.

`src/container/context.cpp` then flattens that config into a `ChildContext` —
a fixed 64KB struct with an arena of packed strings. **Why flatten?** Because
of the constraint that dominates everything after `clone()`; see phase 3.

`src/filesystem/rootfs.cpp` validates the rootfs *now*: does it exist, is it a
directory, is it not `/`, is the entrypoint present and executable inside it.
Checking here rather than in the child means a typo produces a clear message
before any namespace, cgroup or veth has been created and must be unwound.

---

## Phase 2 — the cgroup, created *before* the process

`src/cgroup/cgroup.cpp` creates `/sys/fs/cgroup/minicontainer/<id>/` and
writes the limits.

**Why before?** Because `clone3()` accepts `CLONE_INTO_CGROUP` with a
directory fd, so the child is *born* inside its cgroup. The alternative —
clone, then write the pid into `cgroup.procs` — leaves a window in which the
container runs unconfined and could blow past its memory limit before the
write lands.

Two cgroup v2 facts worth being able to state:

- **Delegation is a write to the parent.** Enabling `memory` for children
  means writing `+memory` to the *parent's* `cgroup.subtree_control`, at every
  level from the root down.
- **The no-internal-process rule.** A cgroup cannot hold both processes and
  controller-enabled children. That is why there is a scope directory holding
  no processes, with one leaf per container — and why `EBUSY` on a
  `subtree_control` write means "this cgroup contains processes".

---

## Phase 3 — `clone3()`, and the constraint nobody expects

```
clone3(CLONE_NEWPID | CLONE_NEWNS | CLONE_NEWUTS | CLONE_NEWIPC
     | CLONE_NEWNET | CLONE_PIDFD | CLONE_INTO_CGROUP)
```

**Why `clone3` and not `fork()` + `unshare()`?** `unshare(CLONE_NEWPID)` does
not move the caller into the new PID namespace — only its future children. You
would need a second fork, with a half-configured process in between. `clone3`
creates the process directly in every requested namespace, atomically. It also
uniquely offers `CLONE_INTO_CGROUP` and `CLONE_PIDFD`.

**`CLONE_PIDFD`** gives a handle immune to PID reuse. Signalling by raw pid
always races the kernel recycling that pid onto an unrelated process — a real
bug class, not a theoretical one.

**Now the constraint.** Between `clone()` and `execve()`, the child may hold a
malloc lock inherited from a thread that does not exist in its address space.
A single allocation can deadlock it *forever*, with no diagnostic. So every
child-side function in this codebase:

- returns `ChildStatus` (a POD), never `Expected<T>` (which owns a string)
- uses stack buffers and raw syscalls
- logs with a single `write(2)` of a literal, never a formatted string

This is enforced mechanically by `scripts/check-child-purity.sh` in CI, not
merely by convention.

---

## Phase 4 — the handshake

The child blocks on a pipe immediately. Several things must happen after it
exists but before it runs:

```
parent                          child
------                          -----
                                blocks reading the sync pipe
write /proc/<pid>/setgroups "deny"
write /proc/<pid>/uid_map
write /proc/<pid>/gid_map
create veth, move peer into netns
send 'G'                    -->  wakes, runs the setup steps
read the error pipe:             on failure: write a ChildErrorWire, _exit
  EOF       => started           on success: execve
  wire data => reconstruct the Error
```

**Why the parent writes the uid maps.** With `CLONE_NEWUSER` the child starts
with *no* valid mapping — its uid reads back as the overflow uid — and only a
process outside the namespace may write the map. So the child cannot do it
itself, and must wait.

**Why `setgroups` must be denied first.** The kernel refuses the `gid_map`
write otherwise. Keeping `setgroups` available in a new user namespace would
let an unprivileged user *drop* supplementary groups and so gain access to
files protected by a negative group permission.

**Why the error pipe works.** Its write end is `O_CLOEXEC`, so a successful
`execve` closes it and the parent's `read()` returns EOF. No timeout, no
polling: EOF means "it got all the way to your program", data means "here is
the step that failed and its errno".

---

## Phase 5 — the setup steps, in order

`src/container/steps.cpp` runs a table of `{Op, function}` pairs. The order is
load-bearing:

1. `sethostname` — the UTS namespace.
2. **Make mount propagation private.** Without this, mounts made here can
   propagate back to the host, because propagation defaults to shared.
3. **Bind the rootfs onto itself.** `pivot_root` requires `new_root` to be a
   *mount point*; a plain directory is not one and fails EINVAL.
4. **Mount `/proc`, `/sys`, `/dev` (tmpfs), device nodes, `/dev/pts`,
   `/tmp`** — all against `<rootfs>/...`, *before* the pivot. Mounting `/proc`
   afterwards would need a working `/proc` to resolve the mount.
5. Bind mounts from `--volume`: `MS_BIND`, then a *separate*
   `MS_REMOUNT|MS_RDONLY` call — the two cannot be combined in one call.
6. Configure the network interface (raw ioctls; no shelling out here).
7. **`pivot_root`**, then `chdir("/")`.
8. **`umount2(MNT_DETACH)`** the old root. Until this, the host filesystem is
   still reachable and the isolation is not real.
9. `chdir` to `--workdir` — after the pivot, so it resolves inside the new
   root.
10. **`no_new_privs`**, then **drop capabilities**, then **seccomp**.

**Why `chroot` is not enough** (the classic question): `chroot` moves only the
process's root *pointer*; the old root stays mounted and reachable. A process
holding an fd to a directory outside the new root can `chroot` again and walk
out. `pivot_root` moves the mount itself, and after `MNT_DETACH` the old root
is gone from this namespace's tree.

**Why that privilege order.** `seccomp(SECCOMP_SET_MODE_FILTER)` requires
either `CAP_SYS_ADMIN` or `no_new_privs`. We are dropping `CAP_SYS_ADMIN`
precisely because a container should not have it — so `no_new_privs` must come
first. And capabilities must survive until every mount above is done, because
mounting and `mknod` need them.

Within `switch_user`: `setgroups`, then `setgid`, then `setuid`. Once uid is
non-zero you can no longer change gid, so a setuid-first sequence silently
leaves the process in the root group.

---

## Phase 6 — PID 1 is not your program

The child forks once more. The **init shim** becomes PID 1; your entrypoint is
its child.

**Why.** The kernel does not apply *default* signal actions to PID 1. A shell
that never installs a SIGTERM handler dies to SIGTERM as an ordinary process,
but as PID 1 it ignores it — so `stop` would wait out its full timeout and
SIGKILL every container. PID 1 must also reap orphans, or they pile up as
zombies until `pids.max` is exhausted.

The shim uses `signalfd` + `poll()` rather than a signal handler: a handler
runs asynchronously and may only touch async-signal-safe functions, whereas an
fd turns "handle a signal" into ordinary, ordered code.

It forwards signals to the entrypoint's process *group*, so `sh -c 'sleep
100'` takes `sleep` down with it — which requires the shim to make the
entrypoint a group leader first, since a cloned child inherits its parent's
pgid. Getting that wrong makes the forward a silent no-op; it was a real bug
in this project, found by writing the test for it.

---

## Questions this document should let you answer

- Why does `unshare(CLONE_NEWPID)` not put the caller in the new namespace?
- Why must the parent write `uid_map`, and why is `setgroups` denied first?
- What is the double-chroot escape, and why does `pivot_root` prevent it?
- Why is `MNT_DETACH` used rather than a plain unmount?
- Why can a container's PID 1 ignore SIGTERM, and what fixes it?
- Why does cgroup v2 forbid processes in a cgroup with controller-enabled
  children?
- What can `CLONE_INTO_CGROUP` do that writing `cgroup.procs` cannot?
- Why must code between `clone()` and `execve()` avoid `malloc`?
- Why is `no_new_privs` set before the seccomp filter?
- Why is a container that exits 42 not a runtime failure?

If any of those is unclear, the file named in the relevant phase is the place
to look — each carries a header comment explaining the reasoning, not just the
mechanics.
