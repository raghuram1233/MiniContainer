# Feature Matrix

Status legend: **Done** = implementation exists, compiles, and has been
exercised. **Partial** = the underlying mechanism works and is tested, but the
container-facing feature built on it does not exist yet. **In progress** =
actively being written this wave. **Planned** = designed (often in Tier-0
header commentary) but no `.cpp` exists yet.

This table is the ground truth for implementation state. If anything else in
these docs implies more is working than this table says, this table wins.
Last updated 2026-08-30 — see the README's Status section for
narrative detail and the verification results behind every **Done** below.

## Foundation

| Feature | Status | Notes |
|---|---|---|
| Error model (`Expected<T>`, `Error`, `Op` enum) | Done | Header-only design frozen in `errors.h`; this is a real, compilable interface |
| Child-side no-alloc error channel (`ChildStatus`, `ChildErrorWire`) | Done | Frozen in `errors.h` |
| Rollback / ScopeGuard transaction helpers | Done | Frozen in `errors.h` |
| Structured logging (parent + async-signal-safe child sink) | Done | Frozen in `logging.h` |
| `ContainerConfig` / `Resources` / `NetworkConfig` / `SecurityConfig` | Done | Frozen in `config.h`; `validate()` is pure, no syscalls |
| Syscall flag formatters, small file helpers | Done | Frozen in `syscall.h` |
| `Fd` / `Pipe` RAII types | Done | Implemented in `src/process/fd.cpp`; move/self-move/CLOEXEC covered by unit tests |
| CLI argv parsing (`ParsedCommand`) | Done | `src/cli/parser.cpp`; 57 unit tests, including the flag/positional boundary and `--` handling |
| CLI dispatch | Done | `src/cli/commands.cpp` + `src/cli/main.cpp`; `version`/`help` work, every runtime-backed verb exits 90 |

## Process layer

| Feature | Status | Notes |
|---|---|---|
| `clone_process()` via `clone3()` | Done | `src/process/clone.cpp`; verified under root creating PID/UTS/user namespaces |
| `CLONE_INTO_CGROUP` support probe | Done | `clone3_into_cgroup_supported()` implemented; the cgroup wiring that consumes it is still Planned |
| Parent/child uid_map handshake (3-pipe sync) | Done | Implemented; an integration test proves an unmapped uid reads back as the overflow uid, which is the reason the handshake exists |
| Init shim (PID 1: signal forwarding, zombie reaping) | Done | `src/process/init_shim.cpp`; verified reaping a reparented orphan while tracking its own child |
| `open_namespace()` / `join_namespace()` (setns) | Done | `src/process/namespace_join.cpp`; round-trip verified on the caller's own UTS namespace |
| pidfd-based signalling | Done | `signal_process()` implemented; verified signalling a child through a `CLONE_PIDFD` handle |

## Namespaces

| Namespace | Status | Notes |
|---|---|---|
| PID | Partial | `clone3(CLONE_NEWPID)` works and the child is really PID 1 (integration-tested); the in-container setup that makes it useful (mounting `/proc`) is Planned. See `docs/namespaces.md` |
| UTS | Partial | `CLONE_NEWUTS` works and hostname isolation is integration-tested; applying `ContainerConfig::hostname` is Planned |
| Mount | Planned | |
| IPC | Planned | |
| Network | Planned | |
| User | Partial | `CLONE_NEWUSER` plus the parent-side uid_map handshake work and are integration-tested; opt-in per `SecurityConfig::userns`, default off |
| Cgroup | Planned | |
| Time | Planned | Lowest priority; least commonly tested in interviews |

## Filesystem

| Feature | Status | Notes |
|---|---|---|
| Rootfs bind mount + `pivot_root` | Done | `src/filesystem/{mount,pivot}.cpp`; verified by running a container in a busybox rootfs |
| `/proc`, `/sys`, `/dev` population | Done | Verified: a container sees 5 processes in its own `/proc`, not the host's |
| Device node creation (`mknod`) | Planned | Fails inside a rootless user namespace on some kernels without extra capability handling — see `docs/troubleshooting.md` |
| `/dev/pts` mount | Done | |
| Bind mounts from `ContainerConfig::bind_mounts` | Done | Implemented; not yet covered by a test |
| Read-only rootfs remount | Done | Gated by `SecurityConfig::readonly_rootfs`; not yet covered by a test |

## Cgroups v2

| Feature | Status | Notes |
|---|---|---|
| Hierarchy detection + `subtree_control` probing | Planned | Must probe, not assume — see measured values in `docs/cgroups.md` |
| `memory.max` / `memory.swap.max` | Planned | |
| `cpu.max` (quota/period) | Planned | |
| `pids.max` | Planned | |
| `cpuset.cpus` | Planned | |
| `stats` (reading cgroup accounting files) | Planned | |

## Networking

| Feature | Status | Notes |
|---|---|---|
| `NetworkMode::None` (loopback only) | Planned | |
| `NetworkMode::Bridge` (veth + bridge + NAT) | Planned | |
| `NetworkMode::Host` | Planned | |
| Port mapping (`-p 8080:80`) | Planned | On WSL2, also requires `netsh portproxy` or mirrored networking on the Windows side — see `docs/networking.md` |
| DNS configuration inside container | Planned | |

## Security

| Feature | Status | Notes |
|---|---|---|
| Capability drop (`cap_drop` / `cap_add` / bounding set) | Done | `src/security/capabilities.cpp`; the ordering rules are in `security.h` |
| `no_new_privs` | Planned | On by default per `SecurityConfig` |
| Seccomp filter (default profile) | Done | `src/security/seccomp.cpp`; a syscall absent on this architecture is skipped rather than aborting the profile |
| Seccomp filter (custom profile path) | Planned | |
| User namespace uid/gid mapping | Planned | Opt-in, off by default |

## Lifecycle / CLI commands

| Command | Status | Notes |
|---|---|---|
| `run` | Planned | End-to-end flow documented in `docs/interview-guide.md`; nothing runs yet |
| `create` / `start` | Planned | |
| `stop` / `kill` | Planned | |
| `exec` (setns into a running container) | Planned | |
| `ps` / `inspect` / `stats` | Planned | |
| `logs` | Planned | |
| `rm` | Planned | |
| State store (`state.json`, atomic write) | Planned | `write_file_atomic()` helper exists as an interface in `syscall.h`; caller code not written |

## Other

| Feature | Status | Notes |
|---|---|---|
| OCI bundle-style config parsing | Planned | `ParsedCommand::bundle_path` exists as a field; parser not written |
| Benchmarking harness | Planned | Methodology documented in `docs/benchmarking.md`; zero numbers collected |
| Integration test suite (root-requiring) | Planned | |
| Unit test suite (no root required) | In progress | Enabled by `ContainerConfig::validate()` and `parse_args()` being pure functions |
