# Cgroups v2

Status: **Planned.** No cgroup module exists yet in `src/cgroup/`. The
`Resources` struct in `include/minicontainer/config.h` and the cgroup-related
`Op` enumerators in `errors.h` (`DetectCgroup`, `EnableController`,
`CreateCgroup`, `WriteCgroupLimit`, `AttachCgroup`, `ReadCgroupStat`,
`RemoveCgroup`) define the intended interface. This document describes the
real, measured cgroup v2 state on the development machine and the mechanics
the implementation must get right.

## The problem cgroups solve

Namespaces make a process *see* a private world. They do nothing to stop
that process from consuming unlimited CPU, memory, or PIDs and starving
everything else on the host. Cgroups (control groups) are the separate
kernel mechanism for *resource accounting and limiting* — a container
needs both: namespaces for isolation, cgroups for containment.

## cgroup v2: the unified hierarchy

Older Linux systems (and Docker's classic mode) used cgroup v1, which had a
*separate* hierarchy per controller (`/sys/fs/cgroup/memory`,
`/sys/fs/cgroup/cpu`, ...) — a process could be in different positions in
each. cgroup v2 replaces this with a **single unified hierarchy**: one tree,
one set of directories, and every controller that's enabled applies to
wherever a process sits in that one tree. MiniContainer targets v2 only.

**Measured on this development machine** (Ubuntu-24.04 WSL, systemd
enabled):

```
$ cat /sys/fs/cgroup/cgroup.controllers
cpuset cpu io memory hugetlb pids rdma

$ cat /sys/fs/cgroup/cgroup.subtree_control
cpu memory pids
```

`cgroup.controllers` lists what the kernel *can* offer at this level.
`cgroup.subtree_control` lists what's actually **delegated to children** —
and these can differ. On this distro, systemd has already delegated `cpu
memory pids` at boot, because systemd itself uses cgroups to manage
services. **On the docker-desktop WSL distro, `cgroup.subtree_control` is
empty** — nothing is delegated by default, because nothing there runs
systemd to do that delegation for you.

**This is the single most important operational fact in this document: the
runtime must PROBE `cgroup.subtree_control`, never assume it.** A
hard-coded assumption that `memory` (or any controller) is available will
work perfectly on one WSL distro and silently produce missing limit files
(`ENOENT` on `memory.max`, not a clear "not delegated" error) on another.
`DetectCgroup` and `EnableController` in the `Op` enum exist as distinct
steps specifically so this probe-then-enable sequence is explicit and
independently diagnosable.

## The no-internal-process rule

cgroup v2 enforces a rule cgroup v1 did not: **a cgroup cannot have both
member processes directly in it AND child cgroups with controllers enabled
on them.** In practice this means: only leaf cgroups hold processes.
`RuntimePaths::cgroup_scope` (default `"minicontainer"`) creates a
non-leaf parent (`/sys/fs/cgroup/minicontainer/`) that holds no processes
itself — only per-container leaf cgroups under it
(`/sys/fs/cgroup/minicontainer/<id>/`) hold the actual container process.

This is also *why* `EBUSY` on a `subtree_control` write means "this cgroup
contains processes": the kernel refuses to let you enable a controller for
child cgroups (which would turn this cgroup into an internal node) while
this cgroup itself still directly holds processes. The fix is always to
move those processes into a child cgroup first, then enable the controller
— never to force the write.

## Delegation: how a controller becomes available in a subtree

Enabling a controller for children is a **write to the parent's**
`cgroup.subtree_control`, not the child's:

```bash
# Enable memory and pids for /sys/fs/cgroup/minicontainer/*'s children
echo "+memory +pids" > /sys/fs/cgroup/minicontainer/cgroup.subtree_control
```

Only after this succeeds does `/sys/fs/cgroup/minicontainer/<id>/memory.max`
and `.../pids.max` exist to be written. A controller must be delegated at
*every* level from the root down to where you want to use it — delegating
it at `/sys/fs/cgroup/cgroup.subtree_control` alone is not enough if
`minicontainer`'s own `subtree_control` doesn't also re-delegate it
downward.

## Resource limit semantics

### `memory.max`

Hard memory ceiling in bytes. Exceeding it triggers the kernel's cgroup-
aware OOM killer *scoped to that cgroup* — it kills a process inside the
cgroup, not an arbitrary process elsewhere on the host, which is the whole
point versus the host-wide OOM killer. `Resources::memory_bytes` maps here;
`parse_memory_size()` in `config.h` parses `"256M"`, `"1G"`, `"512k"`,
or a raw byte count (case-insensitive suffix, 1024-based) into the integer
this file expects. `Resources::memory_swap_bytes` maps to
`memory.swap.max` — note this is *swap on top of* `memory.max`, not a
combined ceiling, unlike cgroup v1's confusingly-named `memory.memsw.limit`.

### `cpu.max`

Written as two space-separated microsecond values: `"<quota> <period>"`.
Every `period` microseconds, the cgroup may consume up to `quota`
microseconds of CPU time *across all its threads combined* — this is a
quota, not a core pin. `Resources::kDefaultCpuPeriodUs = 100000` (100ms) is
the conventional default period. The arithmetic:

```
cpus=0.5  ->  quota = 0.5 * 100000 = 50000  ->  "50000 100000"
cpus=2.0  ->  quota = 2.0 * 100000 = 200000 ->  "200000 100000"
cpus=1.0  ->  quota = 100000                ->  "100000 100000"
```

`Resources::cpu_max_value()` is where this conversion belongs — a pure
computation, unit-testable without a cgroup or root, matching the
`config.h` design philosophy that anything that *can* be pure validation
should be. The literal string `"max"` (unlimited quota) is what you write
instead when `cpus` is unset — never write `0` or omit the file, both of
which mean something different (a real cgroup file that doesn't exist
yet, versus an explicit unlimited).

`Resources::cpu_shares` maps to `cpu.weight` instead — a *relative* share
(default 100, range 1-10000) used when multiple cgroups compete for the
same CPU, orthogonal to the hard `cpu.max` ceiling. A container can have
both: a hard ceiling via `cpu.max` and a relative priority via
`cpu.weight` when contended.

### `pids.max`

A hard cap on the number of tasks (processes+threads) the cgroup may ever
contain, checked at `fork()`/`clone()`/`pthread_create()` time — attempting
to exceed it fails the syscall with `EAGAIN`, it does not kill anything.
This is the direct backstop for the PID-1-not-reaping-orphans failure mode
described in `docs/namespaces.md`: even if the init shim has a bug, a fork
bomb inside the container cannot exceed `pids.max` and starve the host's
process table.

### `cpuset.cpus`

Pins the cgroup's tasks to a specific set of CPU cores (e.g. `"0-3"` or
`"0,2,4"`), unlike `cpu.max`'s time-slicing on any core. Requires the
`cpuset` controller to be delegated separately from `cpu`. Useful for
benchmarking with cache/NUMA effects controlled for — see
`docs/benchmarking.md`.

## `CLONE_INTO_CGROUP`: why creation order matters

As covered in `docs/architecture.md`, `process.h` prefers creating the
cgroup and passing its fd to `clone3()` via `CLONE_INTO_CGROUP` rather than
creating the process first and attaching it to a cgroup afterward. The
reason is a real correctness gap, not just tidiness: between "process
exists" and "process is attached to its cgroup," an attacker-controlled or
just fast-running entrypoint could allocate memory or fork children
completely unconfined. `CLONE_INTO_CGROUP` closes that window by having the
kernel place the new task in the target cgroup atomically as part of
`clone3()` itself. `clone3_into_cgroup_supported()` probes for kernel 5.7+
support and the runtime falls back to writing `cgroup.procs` post-hoc,
logging that the unconfined window exists, when it isn't available.

## Failure modes and common mistakes

- **Assuming a controller is delegated** without checking
  `cgroup.subtree_control` first — works on Ubuntu-24.04-with-systemd,
  breaks silently (missing files, not a clear error) on docker-desktop's
  WSL distro. Always probe.
- **`EBUSY` writing to `subtree_control`** — the cgroup you're writing to
  still has processes directly attached to it; move them to a child cgroup
  first (see the no-internal-process rule above).
- **Writing `cpu.max` in the wrong order** (`"period quota"` instead of
  `"quota period"`) — silently sets a nonsensical limit rather than
  erroring, because both are just integers to the kernel.
- **Forgetting `memory.swap.max` is additive**, not a ceiling that includes
  `memory.max` — a container can use up to `memory.max` RAM *plus*
  `memory.swap.max` swap.
- **Leaving an empty cgroup directory behind** after a container exits —
  `rmdir()` on a cgroup directory fails until every process has actually
  exited (not just been sent a signal); `RemoveCgroup` needs a wait/retry,
  not a single attempt.

## How to debug it

```bash
# Real-time tree view with resource usage, like `ps` for cgroups
systemd-cgls /sys/fs/cgroup/minicontainer

# What's actually delegated at any level
cat /sys/fs/cgroup/minicontainer/cgroup.subtree_control

# Live accounting for one container's cgroup
cat /sys/fs/cgroup/minicontainer/<id>/memory.current
cat /sys/fs/cgroup/minicontainer/<id>/memory.max
cat /sys/fs/cgroup/minicontainer/<id>/cpu.stat
cat /sys/fs/cgroup/minicontainer/<id>/pids.current

# Which cgroup a running process is actually in
cat /proc/<pid>/cgroup

# Was the cgroup OOM killer involved?
dmesg | grep -i "oom\|memory cgroup"
journalctl -k | grep -i oom
```

## Security implications

Cgroups are an availability/fairness control, not a confidentiality
boundary — they stop one container from starving the host or other
containers of CPU/memory/PIDs, but a process that reads `memory.current`
for its own cgroup path can infer something about how it's being
constrained, and a process that escapes its namespaces entirely can often
also walk the cgroup filesystem freely (cgroupfs is not namespace-isolated
by default without `CLONE_NEWCGROUP`, and even then only the *view* is
isolated). Cgroups complement namespaces; neither is a substitute for the
other, and neither is a substitute for capability dropping and seccomp
(`include/minicontainer/security.h`).

## Likely interview questions

- *"Why does cgroup v2 use one hierarchy instead of v1's per-controller
  trees?"* — v1 let a process be in different relative positions in the
  memory tree versus the CPU tree, which made writing correct, race-free
  management tooling extremely hard; v2's unified tree means "which cgroup
  is this process in" has exactly one answer.
- *"What does an `EBUSY` on `cgroup.subtree_control` actually mean, and how
  do you fix it?"* — The cgroup you're delegating from still has processes
  directly in it (violates the no-internal-process rule); move them into a
  leaf child cgroup first.
- *"How would you give a container exactly 1.5 CPUs?"* — `cpu.max` =
  `"150000 100000"` (1.5 * 100000 quota over a 100000us period), not
  `cpuset.cpus` (which pins to specific cores rather than limiting total
  compute).
- *"Why is `CLONE_INTO_CGROUP` better than clone-then-attach?"* — It
  removes the window where the newly created process runs completely
  unconfined before the parent gets around to writing its pid into
  `cgroup.procs`.
- *"Your container's memory.max is set but the process is still killed by
  the host OOM killer instead of the cgroup one — why?"* — Almost always
  means the controller wasn't actually delegated/enabled down to that
  cgroup (check `subtree_control` at every level), so the write to
  `memory.max` either failed or landed on a cgroup with no memory
  controller attached, leaving the process effectively unconfined and
  subject to the system-wide OOM killer instead.
