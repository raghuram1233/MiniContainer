# Architecture

This document describes MiniContainer's design as expressed in the frozen
Tier-0 headers (`include/minicontainer/{errors,logging,config,syscall,
process}.h`). It is architecture, not a status report - for what is actually
implemented, see the README's Status section and Feature Matrix.

## Design principle: the parent/child split

The single most consequential design decision in this codebase is that
**everything after `clone()` and before `execve()` runs under a different
rulebook than everything else**. `process.h` puts it plainly: `child_fn`
"MUST NOT allocate, take a lock, or throw." `errors.h` explains why:

> If another thread held the malloc lock at the instant of clone(), the
> child's allocator is permanently wedged and the next allocation deadlocks
> forever.

This one constraint shapes the whole codebase:

- **Two error types.** The parent uses `Expected<T>`/`Error`, which
  allocates `std::string`s freely. The child uses `ChildStatus` - a POD
  `{Op op; int err;}` - and reports failure by `memcpy`-ing a fixed-size
  `ChildErrorWire` (200 bytes, `static_assert`-checked to fit in `PIPE_BUF`)
  onto a pipe. No allocation, ever, on the child path.
- **Two logging sinks.** `MC_LOG_*` (parent): `std::ostringstream`, a mutex,
  allocation - completely normal and completely forbidden after `clone()`.
  `MC_CLOG`/`MC_CLOG_N` (child): a single `write(2)` of a preformatted byte
  range to a preserved fd - async-signal-safe, no allocation, no locks. This
  split is mechanically enforced in CI: `MC_LOG_*` must never appear under
  `src/child/` (`scripts/check-child-purity.sh`).
- **Two propagation macro families**, but the same shape: `MC_TRY`/
  `MC_CHECK`/`MC_SYS` for the parent's `Expected<T>`, `MC_CHILD_SYS` for the
  child's `ChildStatus`.

## Why clone3() and not fork() + unshare()

Quoting `process.h` directly, because this is the kind of design reasoning
an interviewer will probe and the header states it precisely:

> fork() then unshare(CLONE_NEWPID) does NOT move the caller into the
> new PID namespace - it only arranges for its *children* to be created
> there. You would need a second fork, and in between the process sits
> half-configured. clone3() creates the process directly in every
> requested namespace in one atomic step, with no such window.

clone3() also provides two flags plain clone() does not:

- **CLONE_INTO_CGROUP**: the child is born already inside its cgroup, so
  there is no interval where it runs unconfined and could exceed its memory
  limit before the parent manages to write its pid into `cgroup.procs`.
- **CLONE_PIDFD**: a handle immune to PID reuse. Signalling by raw pid
  always races against that pid being recycled onto an unrelated process;
  `signal_process()` prefers `pidfd_send_signal` for exactly this reason,
  falling back to `kill(2)` only when a pidfd isn't available.

`clone3_into_cgroup_supported()` exists because CLONE_INTO_CGROUP needs
kernel 5.7+; on older kernels the runtime falls back to writing
`cgroup.procs` after the fact and logs that the brief unconfined window
exists rather than silently pretending it doesn't.

## The user-namespace ordering problem and the handshake

CLONE_NEWUSER creates a child with no valid uid mapping. Until the
**parent** writes `/proc/<pid>/uid_map`, almost every privileged operation
inside the child fails - and only the parent can write that file, and only
after the child exists. That forces a rendezvous, implemented as a
three-pipe handshake (`process.h`, reproduced here because the exact
sequencing matters):

```
parent                              child (post-clone)
------                              ------------------
                                     blocks reading sync pipe
write /proc/<pid>/setgroups "deny"
write /proc/<pid>/uid_map
write /proc/<pid>/gid_map
create veth, move peer into netns
send 'G' on sync pipe          -->  wakes, runs the setup step table
                                     on failure: write ChildErrorWire to
                                       the error pipe, then _exit(127)
                                     on success: execve()
read error pipe:                    (execve closes it, via CLOEXEC)
  EOF-marker  => container started
  wire data   => reconstruct the Error
```

Two details worth internalizing:

1. **Ordering of setgroups/uid_map/gid_map is not arbitrary.**
   `setgroups` must be denied *before* `gid_map` is written, or the kernel
   refuses the `gid_map` write outright. The reason is a real privilege-
   escalation vector: leaving `setgroups` available inside a new user
   namespace would let an unprivileged user *drop* supplementary groups and
   thereby gain access to files protected by a negative group permission
   (a file readable by "everyone except group X").
2. **The error pipe's O_CLOEXEC is load-bearing, not incidental.** A
   successful `execve()` closes all O_CLOEXEC fds automatically - so the
   parent reading end-of-file on that pipe *is* the success signal. There is
   no extra "I'm done" message to send and no window where a failure could
   be mistaken for success: either the pipe closes because `execve()`
   happened, or it stays open and something (a wire-format error) arrives.

## PID 1 in the container: the init shim

Two kernel behaviors around PID 1 in a namespace break a naive container if
you don't account for them (`process.h`):

1. **The kernel does not apply default signal dispositions to PID 1.** A
   plain `/bin/sh` running as PID 1 inside the namespace will *ignore*
   SIGTERM unless it explicitly installs a handler - so `minicontainer
   stop` would hang and fall through to SIGKILL every time.
2. **Orphans reparent to PID 1.** Any process in the namespace whose parent
   dies gets reparented to PID 1. If PID 1 never reaps them, they accumulate
   as zombies until `pids.max` is exhausted.

`run_init_shim()` addresses both: it forwards signals to the real
entrypoint and reaps orphans, using `signalfd` so the whole thing is an
ordinary `poll()` loop instead of hand-written async-signal-safe signal
handlers.

## Exec / setns ordering

`join_namespace()`'s doc comment states an ordering constraint that is easy
to get backwards: a user namespace must be joined before the namespaces it
owns, and joining a PID namespace affects only children created afterward -
the caller itself stays where it is. In other words, `setns(CLONE_NEWPID)`
does not teleport the calling thread into the new PID namespace; only
processes it subsequently forks appear there with a new PID 1 view. This is
why `minicontainer exec` has to fork *after* the setns calls, not run
logic directly in the caller.

## Everything is a ContainerConfig

`config.h`'s framing is deliberate: "Nothing downstream of this struct ever
looks at argv or at config.json again." Both the CLI parser and the (future)
OCI-style bundle parser produce a `ContainerConfig`; the state store
round-trips one. This is what keeps configuration parsing decoupled from
runtime logic, and it's why `ContainerConfig::validate()` is a *pure*
function - no syscalls, no filesystem access - so the entire structural
validation path (name/hostname charset, non-empty args, limits in range,
known capability names, parseable CIDRs) is unit-testable without root.
Filesystem-dependent checks (does the rootfs exist, does it contain the
entrypoint) are explicitly deferred to a future `Runtime::preflight()`,
never mixed into `validate()`.

## RuntimePaths: containment by construction

`RuntimePaths` (state root, cgroup root, cgroup scope) exists so that
everything MiniContainer creates lives under these roots - the runtime
never touches a cgroup, mount, or interface outside them. That's what makes
cleanup safe - a bug in cleanup logic can, at worst, damage something under
`/var/lib/minicontainer` or `<cgroup_root>/minicontainer/<id>`, never an
arbitrary host path. `RuntimePaths::from_env()` reads
`MINICONTAINER_ROOT`/`MINICONTAINER_CGROUP_ROOT` specifically so integration
tests can redirect every write into a scratch directory.

## Rollback: setup as a transaction

Container setup acquires a chain of privileged resources in order: cgroup,
clone'd process, veth pair, mounts. If step N fails, steps N-1..0 must be
undone in reverse, or the host accumulates orphaned cgroups and dangling
veth interfaces. `Rollback` (in `errors.h`) is an ordered ledger of undo
actions - `push()` in acquisition order, `run()` unwinds most-recent-first,
`dismiss()` commits (the caller now owns the resources). One subtlety
called out directly in the header: cleanup closures must capture only
copyable state (paths, ints, names) - never a move-only `Fd` - because
`std::function` requires a copyable callable; capture a raw `int` fd
instead of a UniqueFd wrapper.

## Where this lives in the module tree

See `docs/dependency-graph.md` for the full tier breakdown and the
`src/{cli,process,namespace,filesystem,cgroup,network,security,container,
child,runtime,monitoring,logging}` directory structure it maps onto.
