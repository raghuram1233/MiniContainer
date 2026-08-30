# Linux Namespaces

Status: **Partial.** The clone-flag half is real and tested:
`clone_process()` creates children in new PID, UTS, and user namespaces, the
parent/child uid_map handshake works, and `open_namespace()` /
`join_namespace()` round-trip — all covered by privileged integration tests
(`tests/integration/test_process_priv.cpp`).

What does not exist yet is everything a namespace needs *inside* the
container to be useful: no `/proc` is mounted in the new PID namespace, no
hostname is applied in the new UTS namespace, and there is no mount, IPC,
network, cgroup, or time namespace setup at all. Those are the child-side
step functions of `src/namespace/`, which is still empty. Treat the rest of
this document as the design and teaching reference they will be built
against.

## What problem namespaces solve

A normal Unix process sees one global view of everything: one PID space, one
hostname, one filesystem tree, one network stack, one set of System V IPC
objects, one set of user/group IDs, one set of mounted filesystems. Two
unrelated processes on the same machine cannot both believe they are PID 1,
cannot both bind the same TCP port without one seeing the other's socket,
cannot each have a private `/` that hides the other's files. A container is
fundamentally the claim "give this process (and its children) its own
private version of each of those global resources" — and namespaces are the
kernel mechanism that makes that claim true, enforced by the kernel itself
rather than by convention or by a language runtime's cooperation.

## The eight namespace types

| Type | Flag | `clone(2)` since | What it privatizes |
|---|---|---|---|
| Mount | `CLONE_NEWNS` | 2.4.19 (2002) | The set of mounted filesystems and their mount points |
| UTS | `CLONE_NEWUTS` | 2.6.19 | Hostname and NIS domain name |
| IPC | `CLONE_NEWIPC` | 2.6.19 | System V IPC objects and POSIX message queues |
| PID | `CLONE_NEWPID` | 2.6.24 | Process IDs — the namespace has its own PID 1 |
| Network | `CLONE_NEWNET` | 2.6.29 | Network interfaces, routing tables, ports, iptables |
| User | `CLONE_NEWUSER` | 3.8 | UID/GID mapping — root inside can be unprivileged outside |
| Cgroup | `CLONE_NEWCGROUP` | 4.6 | The view of the cgroup hierarchy a process sees under `/proc/self/cgroup` |
| Time | `CLONE_NEWTIME` | 5.6 | Boot time and monotonic clock offsets (for checkpoint/restore) |

`NsType` in `process.h` enumerates all eight (`Pid, Uts, Mount, Ipc, Net,
User, Cgroup, Time`), and `ns_type_name()`/`ns_proc_name()` map each to its
human name and its `/proc/<pid>/ns/<name>` entry (`pid`, `uts`, `mnt`, ...).

## Deep dive: PID namespace

**The problem it solves.** Without namespace isolation, every process on
the host shares one PID space; a container's process tree is fully visible
to (and killable by, given permission) the host, and the container cannot
have a stable "PID 1" of its own the way a real boot environment does.

**The Linux primitive.** `CLONE_NEWPID` gives the calling process's
children a new, private PID space. The first process created in it becomes
PID 1 *of that namespace* (while still having a different, ordinary PID in
every ancestor namespace — PID namespaces nest, and a process has one PID
per namespace it's visible in).

**How MiniContainer uses it.** The process `clone_process()` creates with
`CLONE_NEWPID` set becomes the container's PID 1. `process.h` is explicit
that this process should be `run_init_shim()`, not the user's entrypoint
directly — see below for why.

**What happens internally (kernel-level).** The kernel keeps a stack of
`struct pid_namespace`, one per nesting level, each with its own PID
allocator starting at 1. A `struct task_struct` has one `pid` per
namespace it's visible from, so `getpid()` inside the container returns 1
(or whatever position in that namespace) while the host's `ps` shows a
large, ordinary host PID for the same task. When PID 1 of a namespace
exits, the kernel **immediately and forcibly kills every other process in
that namespace** — there's no orphan cleanup grace period; this is a hard
kernel invariant, not a policy.

**Why PID 1 is special — the two traps.** These are directly called out in
`process.h`'s design commentary, because they break naive implementations:

1. **No default signal dispositions.** For every other process, an
   unhandled `SIGTERM` terminates it. For PID 1 in a namespace, the kernel
   does *not* apply the default action for a signal PID 1 hasn't explicitly
   handled — a plain `/bin/sh` running as PID 1 will silently ignore
   `SIGTERM`. If MiniContainer ran the user's shell as PID 1 directly,
   `minicontainer stop` would hang until it escalated to `SIGKILL` on every
   single container. This is the entire reason `run_init_shim()` exists —
   it's a small process that *does* handle signals properly and forwards
   them to the real entrypoint.
2. **Orphan reaping.** Any process whose parent dies gets reparented to PID
   1 of its namespace (this mirrors host `init`'s role). If PID 1 never
   calls `wait()`/`waitpid()` on them, they become zombies that never leave
   the process table, and eventually you hit `pids.max` for no
   user-visible reason. `run_init_shim()`'s `reap_orphans` option exists
   specifically to `waitpid(-1, ..., WNOHANG)` in a loop.

**Failure modes and common mistakes.**
- Running the user's process directly as PID 1 (skipping the init shim) —
  works for a quick demo, breaks signal handling and reaping.
- Forgetting that PID 1 dying kills the whole namespace: if your init shim
  crashes, every process the container was running dies with it, with no
  chance to log why.
- Assuming `getpid()` returns the same value inside and outside the
  container — it doesn't; that's the entire point.

**How to debug it.**
```bash
lsns -t pid                       # list PID namespaces on the system
readlink /proc/<pid>/ns/pid       # e.g. pid:[4026532345]
nsenter -t <pid> -p -r ps aux     # see the process tree as PID 1 sees it
cat /proc/<pid>/status | grep NSpid   # PID in every ancestor namespace, innermost first
```

**Security implications.** PID namespace isolation alone does not stop a
process from *seeing* host resources through other channels (an open file
descriptor inherited across the boundary, a shared mount, `/proc/<pid>` of
a host process if the mount namespace exposes it). It's one layer of a
defense that needs the other seven namespace types plus capabilities and
seccomp to be meaningful — see `include/minicontainer/security.h`.

**Likely interview questions.**
- *"Why can't a container's process just call `kill -9 1` from inside to
  restart cleanly?"* — Because killing PID 1 tears down the whole
  namespace; this is a kernel invariant, not something the runtime can
  intercept.
- *"What happens if the same binary is PID 1 in two different containers at
  once?"* — Fully independent; each PID namespace has its own numbering, so
  `getpid()==1` is true in both simultaneously with no conflict, because
  they're different `struct pid_namespace` instances.
- *"Why does `docker exec` sometimes show a different PID for the same
  process than `ps` inside the container?"* — Because a process has one PID
  per namespace it's visible from; the host tool and the in-container tool
  are reading different namespaces' views of the same `task_struct`.

## Deep dive: UTS namespace

**The problem it solves.** Without isolation, `sethostname()` is global —
one container setting its hostname would change it for the entire host and
every other container.

**The Linux primitive.** `CLONE_NEWUTS` privatizes the two fields
`uname(2)` reports that are actually mutable: `nodename` (hostname) and
`domainname` (NIS domain).

**How MiniContainer uses it.** `ContainerConfig::hostname` (defaulting to
the container id when unset) is written via `sethostname(2)` inside the
child, after `CLONE_NEWUTS` has taken effect but *before* any operation
that could be observed from outside the namespace. This is the
`SetHostname` step in the child setup sequence (see the `Op` enum in
`errors.h`).

**What happens internally.** `uname(2)`'s nodename/domainname live in
`struct uts_namespace`, one instance per UTS namespace, shared-copy-on-clone
just like PID. `sethostname(2)`/`setdomainname(2)` write to the calling
process's namespace only.

**Failure modes.** Setting the hostname *before* `CLONE_NEWUTS` takes
effect (or without the flag at all) changes the host's hostname — an easy,
dangerous mistake in a runtime with root privilege. Also: hostname length
is capped at 64 bytes by the kernel; `is_valid_hostname()` in `config.h`
enforces RFC 1123 label rules (max 63 chars) ahead of time so this fails at
`validate()` time, not as an opaque `ENAMETOOLONG` from the kernel deep
inside child setup.

**How to debug it.**
```bash
nsenter -t <pid> -u hostname          # read hostname inside the namespace
readlink /proc/<pid>/ns/uts
```

**Security implications.** Low on its own — hostname spoofing is not a
privilege escalation — but a shared UTS namespace between "isolated"
containers is a clear signal that isolation elsewhere is probably
incomplete too, since UTS is one of the cheapest namespaces to get right.

**Likely interview question.** *"Why is UTS namespace isolation considered
one of the 'easy' namespaces?"* — No ordering dependencies on other
namespaces, no privileged mapping step like user namespaces, and a single
syscall (`sethostname`) is the entire attack surface.

## Deep dive: mount namespace

Mount namespaces get their own document because of mount *propagation*,
which is subtle enough to deserve full treatment — see `docs/filesystem.md`
for `MS_REC|MS_PRIVATE`, `pivot_root`, the chroot-is-not-a-jail argument,
and `MNT_DETACH`.

**The short version here:** `CLONE_NEWNS` (the oldest namespace flag,
confusingly *not* named `CLONE_NEWMNT`, for historical reasons — it was the
only namespace type when it was added) gives the process its own list of
mount points, so that mounting or unmounting something inside the
namespace does not affect the host or other containers' views, *provided*
propagation is configured correctly first.

## Deep dive: user namespace

**The problem it solves.** Traditional container isolation runs the
container's root as the host's real root (uid 0) — every namespace boundary
is enforced by the kernel, but if a process manages to escape any one of
them (a kernel bug, a misconfigured bind mount, a `/proc` write it
shouldn't have), it is instantly root on the host. User namespaces close
that specific gap: root *inside* the container can be an ordinary,
unprivileged uid *outside* it.

**The Linux primitive.** `CLONE_NEWUSER` gives the process its own
UID/GID mapping table. Inside the namespace, `getuid()` can report 0 while
the *actual* credential the kernel checks against host resources is
whatever `/proc/<pid>/uid_map` maps that namespace-uid to on the host.
Capabilities (see `include/minicontainer/security.h`) are also namespace-relative: a
process can hold `CAP_SYS_ADMIN` *within its own user namespace* — enough
to, say, create further namespaces or mount some filesystem types — while
holding nothing at all against the host.

**How MiniContainer uses it.** Opt-in, off by default —
`SecurityConfig::userns` — because, as `config.h` notes, enabling it "costs
mknod, binding privileged ports, and devpts gid=5": a real, working user
namespace setup has to solve several secondary problems (device node
creation permissions, low port binding, `/dev/pts` group ownership) that a
host-uid-0 container sidesteps entirely. `userns_host_uid`/
`userns_host_gid`/`userns_size` configure the mapping: which host uid maps
to container uid 0, and how large a contiguous range is mapped (default
65536, letting the container have its own full 16-bit uid space).

**What happens internally.** This is the subject of the entire "user-
namespace ordering problem" design note in `process.h` and
`docs/architecture.md`: the child is created with `CLONE_NEWUSER` and
starts with *no* valid mapping at all, meaning nearly every privileged
syscall fails inside it until the parent writes `/proc/<pid>/uid_map` and
`/proc/<pid>/gid_map`. Only the parent can write those files (a security
requirement — otherwise a process could grant itself an arbitrary
mapping), and only after the child exists, hence the three-pipe handshake
described in `docs/architecture.md`. `setgroups` must be written `deny`
*before* `gid_map`, or the kernel refuses the `gid_map` write — closing off
a real privilege-escalation path where an unprivileged user could otherwise
drop supplementary groups to gain access via a negative group permission.

**Failure modes and common mistakes.**
- Writing `gid_map` before denying `setgroups` — the kernel rejects it.
- Assuming a mapped "root" inside the namespace can do host-root things
  like load a kernel module or set the system clock — it cannot; those
  capabilities aren't namespace-relative to that degree.
- `mknod` failing inside a user-namespaced container even with `CAP_MKNOD`
  in the namespace — some device node types are still blocked; see
  `docs/troubleshooting.md`.
- Forgetting `userns_size` must be large enough for the packages the
  container image expects to `chown` files across (e.g. a build image doing
  wide uid ranges) — 65536 (a full namespace) is the safe default.

**How to debug it.**
```bash
cat /proc/<pid>/uid_map /proc/<pid>/gid_map
cat /proc/<pid>/status | grep Cap    # CapInh/CapPrm/CapEff/CapBnd/CapAmb
nsenter -t <pid> -U -r id            # what id(1) reports inside the user namespace
```

**Security implications.** This is the single biggest improvement to
container isolation available without a hypervisor: it turns "kernel bug in
namespace code" from "instant host root" into "root within a sandboxed
uid range that owns nothing on the host filesystem by default." It is not
a complete defense on its own — combine with seccomp and capability
dropping (`include/minicontainer/security.h`).

**Likely interview questions.**
- *"Why must the parent, not the child, write uid_map?"* — Because if the
  child could write its own mapping, an unprivileged process could map
  itself to any uid it wants, including 0 on the host — the whole point of
  the namespace's security boundary depends on the mapping being set by
  something with more privilege than the mapped process itself.
- *"What's the practical cost of enabling user namespaces?"* — Every place
  the code assumed "we're host root, this just works" (binding port 80,
  `mknod`, some `/dev/pts` operations) now needs an explicit capability or
  workaround, because inside-namespace root usually isn't equivalent to
  actual host privilege for those operations.

## Deep dive: network namespace

Covered in depth in `docs/networking.md` (veth pairs, bridge, NAT, the
WSL2-specific double-NAT wrinkle). Short version: `CLONE_NEWNET` gives the
process its own network stack — interfaces, routing table, iptables rules,
sockets, `/proc/net` — down to just loopback unless something (a veth pair)
connects it to anything else.

## IPC, cgroup, and time namespaces (brief)

- **IPC** (`CLONE_NEWIPC`): private System V shared memory segments,
  semaphores, and message queues, plus POSIX message queues. Rarely
  attacked directly, but leaving it shared lets one container read another's
  SysV shared memory by guessing/enumerating IPC keys.
- **Cgroup** (`CLONE_NEWCGROUP`): changes what a process sees under
  `/proc/self/cgroup` and as the root when it walks `/sys/fs/cgroup` from
  inside — without it, a process inside the container can see its full
  cgroup path on the host, which leaks topology information. Does not by
  itself change resource accounting, which is what the *cgroup controllers*
  (see `docs/cgroups.md`) do.
- **Time** (`CLONE_NEWTIME`): the newest namespace (5.6), for offsetting
  `CLOCK_MONOTONIC`/`CLOCK_BOOTTIME` — built for checkpoint/restore
  (CRIU) workloads where a restored process needs to see time as if it
  never stopped. Lowest priority for MiniContainer and least likely to
  come up in an interview compared to the other seven.

## `open_namespace()` / `join_namespace()` and setns ordering

`process.h` declares both around `/proc/<pid>/ns/<name>` — `open_namespace`
opens that magic symlink (each resolves to a unique inode identifying the
namespace instance, which is also what `lsns` groups processes by), and
`join_namespace` wraps `setns(2)` on the resulting fd. The doc comment
states the ordering rule plainly: *"a user namespace must be joined before
the namespaces it owns, and joining a PID namespace affects only children
created afterward — the caller itself stays where it is."* This is why
`minicontainer exec` (joining a running container to run a new command in
it) must: open all the target namespaces first, `setns` into the user
namespace (if any) before the others it owns, then `setns` into PID/mount/
net/etc., then `fork()` — the *forked child*, not the caller, ends up with
PID-namespace-relative PID 1 visibility.

## General debugging toolkit

```bash
lsns                                    # every namespace on the system, by type
lsns -p <pid>                           # namespaces a specific process is in
readlink /proc/<pid>/ns/*               # inode ids identify same-vs-different namespace
nsenter -t <pid> -a <command>           # join every namespace of <pid> and run <command>
nsenter -t <pid> -m -u -i -n -p -r -w <command>  # join specific namespaces individually
findmnt -N <pid>                        # mount namespace's mount table (see docs/filesystem.md)
```

Two processes are in the "same" namespace of a given type exactly when
`stat()` on their respective `/proc/<pid>/ns/<type>` returns the same
device+inode — this is the mechanism `lsns` and `nsenter` build on, and the
one to reach for whenever "are these actually isolated?" needs a real
answer instead of a guess.
