# How MiniContainer Works, and How to Use It

MiniContainer is a small, from-scratch Linux container runtime written in
C++20. It does what Docker/`runc` do under the hood — namespaces, cgroups,
capability dropping, seccomp, a veth/bridge network — with no dependency on
either. This document explains the mechanism end to end, then covers every
command you'd actually run.

If you just want to run a container right now, skip to
[Quick start](#quick-start). If you want to understand *why* a container is
isolated the way it is, read [How it works](#how-it-works) first.

---

## Requirements

- **Linux with cgroup v2 and user namespaces.** On Windows this means
  **WSL2** — WSL1 does not have real namespaces. Verified against
  Ubuntu 24.04 / kernel 6.18 (WSL2).
- **Root**, or enough delegated capabilities — mounting, `pivot_root`,
  creating namespaces, and writing cgroup files all need privilege.
- `libcap`, `libseccomp` (optional but on by default), `iptables` (for
  bridge networking).
- The build tree and any rootfs/state directories must live on a native
  **ext4** path inside WSL (e.g. `~/mc-build`), not on the Windows
  filesystem (`/mnt/c/...`) — drvfs cannot represent device nodes or Linux
  mode bits correctly. Reading source from `/mnt/c/...` is fine; running
  containers from there is not.

---

## How it works

### A container is just a process, configured unusually

There is no "container" object in the kernel. `minicontainer run` creates one
ordinary Linux process using `clone3()`, and gives that call a handful of
flags and a pre-opened file descriptor that make the new process's view of
the world different from its parent's:

- `CLONE_NEWPID` — the child becomes PID 1 in a fresh PID namespace; it
  cannot see or signal any process outside it.
- `CLONE_NEWUTS` — its own hostname.
- `CLONE_NEWNS` — its own mount table, so mounting/pivoting inside it never
  touches the host's.
- `CLONE_NEWIPC` — its own System V IPC and POSIX message queues.
- `CLONE_NEWNET` (bridge/none modes) — its own network stack; empty until a
  veth end is moved into it.
- `CLONE_NEWUSER` (only with `--userns`) — its own uid/gid mapping.
- `CLONE_INTO_CGROUP` — the cgroup is created *before* the clone and its
  fd handed to `clone3()`, so the new process is a cgroup member from its
  very first instruction, not attached a moment later (which would leave a
  window where it could exceed limits or escape accounting).

### The rule that shapes the whole codebase: nothing may allocate between `clone()` and `execve()`

This is the single most consequential design decision in the project. If
another thread held glibc's malloc lock at the instant `clone()` ran, the
child inherits that *locked* state but not the thread that would ever unlock
it — so any `malloc` in the child (a `std::string`, a `std::vector`, a
C++ exception) can deadlock forever. There is no timeout; the process just
hangs.

MiniContainer's architecture is built entirely around avoiding that:

1. **Everything that can allocate — parsing config, resolving capability
   names, compiling a seccomp profile to BPF, running `ip link` commands to
   set up networking — happens in the PARENT, before `clone3()`.**
2. The results are packed into a single flat, fixed-size, ~64KB POD struct
   called `ChildContext` (`include/minicontainer/container.h`): raw C
   strings into a pre-sized arena, integers, fixed-size buffers — never a
   `std::string` or `std::vector` member.
3. The child, immediately after `clone3()` returns 0, runs a fixed
   **step table** of `step_*` functions (`ChildStatus step_foo(const
   ChildContext&) noexcept`) that touch only bare syscalls: `mount`,
   `pivot_root`, `mknod`, `setns`, `prctl`, the raw `seccomp(2)` syscall
   (not libseccomp's own loader, which allocates), `setuid`/`setgid`. Every
   one is `noexcept` and takes its input by `const&` from the arena.
4. Only once every step has succeeded does the child call `execve()` into
   the user's actual command — at which point it's running normal code in a
   normal process, and the allocation restriction no longer applies.

A CI-enforced script, `scripts/check-child-purity.sh`, greps every `step_*`
body for banned allocating constructs, so this invariant can't quietly rot.

### The step-by-step sequence inside the child

In order, once `clone3()` returns inside the child:

1. **`step_make_root_private`** — remounts `/` as `MS_PRIVATE` recursively,
   so nothing this process does to its mount table can propagate back to
   the host's.
2. **`step_bind_rootfs`** — bind-mounts the user's rootfs onto itself. This
   looks redundant but is required: `pivot_root` demands its target be a
   mount point, and a plain directory isn't one until you do this.
3. **`step_mount_proc`**, **`step_mount_dev`**, **`step_mount_tmp`** (and
   optionally `/sys`, `/dev/pts`) — the pseudo-filesystems every normal
   program expects to find.
4. **`step_create_device_nodes`** — `mknod`s `/dev/null`, `/dev/zero`,
   `/dev/random`, etc. as real character devices inside the new root.
5. **`step_pivot_root`** — swaps the process's root to the container's
   rootfs; the old root becomes `/.oldroot`.
6. **`step_umount_old_root`** — lazily unmounts and removes `/.oldroot`, so
   there is no path left from inside the container back to the host
   filesystem at all.
7. **`step_configure_address`** (bridge networking only) — renames the
   veth peer to `eth0` and assigns it the allocated IP (see
   [Networking](#networking-veth--bridge--nat) below).
8. **`step_set_working_dir`** — `chdir`s to `--workdir`.
9. **`step_set_no_new_privs`** — `prctl(PR_SET_NO_NEW_PRIVS, 1)`. Must come
   *before* the seccomp filter: installing a filter without
   `CAP_SYS_ADMIN` requires `no_new_privs` set first, or the kernel returns
   `EACCES`. It's also what stops the container process from regaining
   privilege later by executing a setuid binary like `/usr/bin/passwd`.
10. **`step_drop_capabilities`** — clears every Linux capability outside
    the resolved keep-mask from the permitted, effective, and inheritable
    sets, and clears the bounding set too (so a setuid binary can't
    resurrect a dropped capability across `execve`).
11. **`step_install_seccomp`** — installs the BPF program the parent
    compiled, via the raw `seccomp(SECCOMP_SET_MODE_FILTER)` syscall.
12. **`step_switch_user`** — only with `--userns`:
    `setgroups({})` → `setgid()` → `setuid()`, strictly in that order. Once
    UID is non-zero you can no longer change GID, so doing this out of order
    is a classic way to accidentally leave a process in the root group.
13. **`execve()`** into the user's command.

If any step fails, the child reports which one (by `Op` enum and `errno`)
back to the parent over a pipe and exits — the parent never has to guess
which of a dozen setup operations went wrong.

### Namespaces: PID, UTS, mount, IPC, network, user

Each namespace type isolates one specific kind of kernel-visible state; see
`docs/namespaces.md` for the full failure-mode reference. The one worth
calling out here: joining a namespace via `setns(2)` (what `exec` does) has
an asymmetry — a container started without `--userns` shares the *same*
user namespace as the host, and the kernel refuses `setns(CLONE_NEWUSER)`
into a namespace you're already a member of (`EINVAL`). MiniContainer
detects this (comparing the `(device, inode)` pair of the namespace files,
per `namespaces(7)`) and treats "already there" as success rather than
surfacing a confusing error.

### Cgroups v2: real limits, read back from the host

`--memory`, `--memory-swap`, `--cpus`, `--cpu-shares`, `--pids`, and
`--cpuset-cpus` are written straight into the container's cgroup
(`memory.max`, `cpu.max`, `pids.max`, `cpuset.cpus`) under
`/sys/fs/cgroup/minicontainer/<id>/` before the process is cloned into it.
Delegation (whether `cgroup.subtree_control` grants the controller you're
asking for) is *probed at runtime*, never assumed — it differs between a
systemd-managed WSL distro and something like Docker Desktop's VM. See
`docs/cgroups.md`.

### Security: capabilities, `no_new_privs`, seccomp

- **Capabilities**: a default allow-list keeps enough to run ordinary
  software (e.g. `CAP_CHOWN`, `CAP_NET_BIND_SERVICE`) while excluding
  everything that grants host-level power (`CAP_SYS_ADMIN`,
  `CAP_SYS_MODULE`, `CAP_SYS_BOOT`, `CAP_SYS_TIME`, and others).
  `--cap-drop`/`--cap-add` (including the `ALL` keyword) adjust it —
  drop is applied before add, so the idiomatic hardening recipe
  `--cap-drop=ALL --cap-add=NET_BIND_SERVICE` does what it looks like.
- **seccomp**: a deny-list filter compiled to BPF *in the parent* (compiling
  is an allocating operation) and installed with one bare syscall in the
  child. `--seccomp default` blocks a fixed list of host-dangerous syscalls
  (`mount`, `ptrace`, `setns`, `unshare`, `bpf`, `reboot`, `init_module`,
  clock/hostname changes, and more) with `EPERM` rather than killing the
  process, so the container's own program can report the failure instead
  of just dying with `SIGSYS`. `--seccomp <PATH>` loads a **custom** deny
  list from a plain-text file — one syscall name per line, `#` starts a
  comment, blank lines are ignored:

  ```
  # deny mkdir as an example
  mkdir
  mkdirat
  ```

  `--seccomp off` disables filtering entirely; `--privileged` implies it
  (a filter is meaningless once the process keeps `CAP_SYS_ADMIN`, since it
  could just install a more permissive one itself).

### Networking: veth, bridge, NAT

`--network bridge` does the following, in order, once the container's
network namespace exists:

1. Ensures a Linux bridge exists on the host (creating it if needed).
2. Creates a veth pair. Both ends briefly exist in the **host** namespace
   at creation time — this matters because the container-visible end is
   *not* created with the literal name `eth0`: WSL2 and most cloud VMs
   already have their own host-side `eth0`, and creating a second interface
   with that name in the same (host) namespace fails with `EEXIST`. Instead
   it gets a collision-safe temporary name, and only after the peer is moved
   into the container's own network namespace does `step_configure_address`
   rename it to the literal `eth0` the container actually sees.
3. Moves the peer into the container's netns and assigns it an IP from the
   configured subnet (`--ip`, or auto-allocated).
4. Attaches the host end to the bridge, and NATs outbound traffic via
   `iptables` so the container reaches the internet through the host.
5. `-p/--publish 8080:80` sets up DNAT so traffic to the host's port 8080
   reaches port 80 inside the container. On WSL2 this also needs a Windows
   side `netsh interface portproxy` rule — see `docs/networking.md`.

`net.ipv4.ip_forward` must be `1` on the host or containers get an address
but no route out — the runtime warns about this explicitly rather than
failing silently.

### `exec`: joining a live container

`minicontainer exec NAME CMD` opens `/proc/<pid>/ns/*` for the target
container's namespaces and `setns()`s a freshly forked process into each —
in the order the owning user namespace, then the others, since `setns()`
checks capabilities against the *owning* user namespace of whatever you're
joining. Joining a PID namespace only affects **children created after**
the `setns()` call; the exec'd process itself becomes PID 2 (or higher)
inside, not PID 1, and gets its own view of `/proc` once it forks/execs.

### Lifecycle and state

Every `create`/`run` writes a `state.json` record (PID, config, cgroup path,
network allocation, exit code once it exits) to
`/var/lib/minicontainer/<name>/`. `ps`, `inspect`, `stats`, `stop`, `kill`,
`logs`, and `rm` all read or update that record — there's no daemon; each
CLI invocation is a short-lived process that reads state, does one thing,
and exits.

---

## Quick start

```bash
# Build (see docs/getting-started.md for full WSL2 setup)
cmake --build ~/mc-build -j"$(nproc)"

# Run a container with a memory limit, detached
sudo ~/mc-build/minicontainer run -d --name boxy --rootfs ~/rootfs \
    --memory 64M /bin/sh -c 'sleep 3600'

# See it running
sudo ~/mc-build/minicontainer ps

# Check the limit was actually applied, read from the HOST side
cat /sys/fs/cgroup/minicontainer/boxy/memory.max

# Run a second process inside the SAME container
sudo ~/mc-build/minicontainer exec boxy /bin/sh -c 'hostname; echo pid=$$'

# Live resource stats
sudo ~/mc-build/minicontainer stats boxy

# Stop and clean up
sudo ~/mc-build/minicontainer stop boxy
sudo ~/mc-build/minicontainer rm boxy
```

Everything needs root (or equivalent delegated privilege) — creating
namespaces, mounting, and writing cgroup files all require it.

---

## Command reference

### `run` — create and start a container, then wait for it to exit

```
minicontainer run [FLAGS] (--rootfs PATH CMD [ARGS...] | BUNDLE_DIR)
```

| Flag | Meaning |
|---|---|
| `--name NAME` | container name |
| `--hostname NAME` | UTS hostname (default: container id) |
| `--rootfs PATH` | root filesystem directory |
| `--memory SIZE` | memory limit, e.g. `256M`, `1G` |
| `--memory-swap SIZE` | swap limit |
| `--cpus N` | fractional CPU limit, e.g. `0.5` |
| `--cpu-shares N` | relative CPU weight |
| `--pids N` | max number of processes |
| `--cpuset-cpus LIST` | `cpuset.cpus` value, e.g. `0-3` |
| `--network MODE` | `none`\|`bridge`\|`host` |
| `--ip ADDR` | static container IP (bridge mode) |
| `--dns ADDR` | DNS server (repeatable) |
| `-p, --publish MAP` | publish a port, e.g. `8080:80` or `8080:80/udp` (repeatable) |
| `--cap-add CAP` | add a Linux capability (repeatable) |
| `--cap-drop CAP` | drop a Linux capability (repeatable) |
| `--seccomp MODE` | `off`\|`default`\|`PATH` to a custom profile |
| `--no-new-privs[=BOOL]` | set `no_new_privs` (default: true) |
| `--userns` | enable a user namespace |
| `--privileged` | keep all capabilities |
| `--read-only` | mount the root filesystem read-only |
| `-e, --env KEY=VALUE` | set an environment variable (repeatable) |
| `-w, --workdir PATH` | working directory inside the container |
| `-v, --volume SRC:DST[:ro]` | bind mount (repeatable) |
| `-t, --tty` | allocate a pseudo-TTY |
| `-i, --interactive` | keep stdin open |
| `-d, --detach` | run in the background |
| `--rm` | remove the container when it exits |

The first non-flag argument begins the container's own command line;
everything after it — including tokens that look like flags — is passed
through untouched. Use `--` to separate this tool's flags from the
container's command explicitly:

```bash
minicontainer run --rootfs ./r -- /bin/sh -c "echo hi"
```

### `create` / `start`

```
minicontainer create [FLAGS] (--rootfs PATH CMD [ARGS...] | BUNDLE_DIR)
minicontainer start NAME
```

`create` takes the same flags as `run` but only sets the container up; it
does not start it. `start` starts a previously created container.

### `stop` / `kill`

```
minicontainer stop NAME [--time N]
minicontainer kill NAME [--signal SIG]
```

`stop` asks the container to exit gracefully, then `SIGKILL`s it after `N`
seconds (default 10). `kill` sends a signal immediately — numeric (`9`) or
by name (`TERM`, `KILL`, `HUP`, ...), default `TERM`.

### `exec` — run a command inside a running container

```
minicontainer exec [FLAGS] NAME CMD [ARGS...]
```

| Flag | Meaning |
|---|---|
| `-e, --env KEY=VALUE` | set an environment variable (repeatable) |
| `-w, --workdir PATH` | working directory for the new process |
| `-t, --tty` | allocate a pseudo-TTY |

### `ps` / `inspect` / `stats` / `logs` / `rm`

```
minicontainer ps [-a|--all] [--json]
minicontainer inspect NAME [--json]
minicontainer stats [NAME] [--no-stream]
minicontainer logs NAME [-f|--follow]
minicontainer rm NAME [-f|--force]
```

`ps` lists containers (running only, unless `-a`). `inspect` shows full
detail for one. `stats` shows live cgroup-derived resource usage — all
running containers if `NAME` is omitted. `logs` shows captured
stdout/stderr, optionally following. `rm` removes a stopped container's
state (`-f` to force-remove a running one).

### `version` / `help`

```
minicontainer version
minicontainer help [COMMAND]
```

`help` alone prints the top-level command list; `help <command>` prints the
detail above for that one command.

---

## Where to look next

| Topic | Document |
|---|---|
| Full syscall-by-syscall walkthrough of `run` | `docs/interview-guide.md` |
| Module structure, error/logging model | `docs/architecture.md` |
| Build tier order and why | `docs/dependency-graph.md` |
| Namespace types and failure modes | `docs/namespaces.md` |
| `pivot_root`, mounts, device nodes | `docs/filesystem.md` |
| cgroup v2 limits and delegation | `docs/cgroups.md` |
| veth/bridge/NAT/WSL2 specifics | `docs/networking.md` |
| Full WSL2 setup | `docs/getting-started.md` |
| Common failures and fixes | `docs/troubleshooting.md` |
| Capabilities/seccomp/`no_new_privs` design commentary | `include/minicontainer/security.h` |

See the top-level `README.md` for current implementation status and test
counts — it is the authoritative source of truth on what is done versus
planned.
