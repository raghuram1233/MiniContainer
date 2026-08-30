# Troubleshooting

Every failure in this document was actually hit while building MiniContainer,
not imagined. They are ordered roughly by how much time each one costs before
you work out what it really is.

The general principle: MiniContainer's errors name the operation that failed
(`Failed to mount /proc: ...`) because a bare errno from deep inside container
setup is nearly undiagnosable. If you see an error that does *not* say which
step failed, that is a bug worth reporting.

---

## `mknod` fails with EPERM even as root

**Symptom**

```
minicontainer: Failed to create device node: mknod: Operation not permitted
```

...running as root, on a path you can clearly write to.

**Cause**

The rootfs is on `/mnt/c` (or any Windows drive mount). That is drvfs, which
bridges to Windows over 9p. 9p **cannot represent a device node at all** — so
this is not a permission problem despite what EPERM implies, and no amount of
privilege will fix it.

**Fix**

Put the rootfs on WSL's native ext4:

```bash
scripts/create-rootfs.sh ~/rootfs      # not /mnt/c/...
```

MiniContainer detects this up front — `validate_rootfs` checks the filesystem
type and refuses with an explanation before creating anything — so you should
see the clear message rather than the raw EPERM. If you get the raw EPERM, the
check was bypassed somehow, and that is worth reporting.

**The same constraint applies to the build tree.** `scripts/wsl-build.sh`
refuses to build into a Windows drive mount for this reason.

---

## `stop` takes ten seconds and then kills the container

**Symptom**

```
WARN container web did not exit within 10s; sending SIGKILL
```

...on a container whose entrypoint would normally handle SIGTERM fine.

**Cause**

The kernel does not apply *default* signal actions to PID 1. An ordinary
process that never installs a SIGTERM handler still dies to SIGTERM, because
the kernel's default action applies. PID 1 is exempt — deliberately, so that a
stray SIGTERM cannot destroy a system by accident. Inside a container that
protection is exactly backwards: a shell running as PID 1 simply drops the
signal on the floor.

**Fix**

MiniContainer runs an init shim as PID 1 and the entrypoint as its child, so
the entrypoint is an ordinary process and default signal actions apply again.
If you still see this warning, either:

- your entrypoint really is ignoring SIGTERM (check its own signal handling), or
- it is a long-running process that needs longer — use `stop --time 30`.

You can confirm the shim is in place: inside the container, `ps` shows
`minicontainer` as PID 1 and your entrypoint as PID 2.

---

## The container exits 127 immediately with an `execve` error

**Symptom**

```
minicontainer: container process: Failed to execute container entrypoint:
  execve failed: is the entrypoint present in the rootfs, along with its
  shared libraries?: No such file or directory (ENOENT)
```

**Cause — two possibilities, and ENOENT does not distinguish them**

1. The binary genuinely is not in the rootfs. The path is resolved *inside*
   the container: `/bin/sh` means `<rootfs>/bin/sh`, not the host's.
2. The binary is there, but it is **dynamically linked** and its interpreter
   is not. After `pivot_root` the host's `/lib` is gone, so the dynamic linker
   cannot be found — and the kernel reports that as ENOENT on the binary
   itself, which is thoroughly misleading.

**Diagnosing which**

```bash
ls -l ~/rootfs/bin/sh          # is it there at all?
ldd ~/rootfs/bin/sh            # "not a dynamic executable" = case 1
                               # a list of .so files       = case 2
```

**Fix**

Use a static binary. `scripts/create-rootfs.sh` installs a static busybox by
default precisely to sidestep this. For a dynamically linked binary you must
also copy its interpreter and every library `ldd` lists into the rootfs.

---

## Resource limits silently do nothing

**Symptom**

`--memory 64M` appears to be accepted, but the container uses more than 64M.

**Cause**

The controller was never delegated to our part of the cgroup tree. This
**varies by host and must never be assumed**: the Ubuntu-24.04 WSL distro
(systemd running) has `cpu memory pids` delegated; docker-desktop's WSL distro
has an **empty** `cgroup.subtree_control`, even though both present as
cgroup v2.

**Diagnosing**

```bash
cat /sys/fs/cgroup/cgroup.controllers        # what the kernel offers
cat /sys/fs/cgroup/cgroup.subtree_control    # what is delegated downward
```

MiniContainer probes this and reports an `Op::Unsupported` error naming the
controller rather than skipping the limit. If a limit is quietly ignored with
no error at all, that is a bug.

**Verifying a limit really applied** — read it from the host side, which is
the only check that cannot lie:

```bash
cat /sys/fs/cgroup/minicontainer/<id>/memory.max
# 67108864   <- exactly 64M
```

---

## `EBUSY` when removing a container

**Symptom**

```
minicontainer: container web was only partly removed: cgroup: ... Device or
resource busy
```

**Cause**

A process is still inside the cgroup. cgroup v2 refuses to `rmdir` a cgroup
that is not empty — the kernel is telling you teardown ran too early, not
reporting a transient condition to retry.

Usually it means the entrypoint spawned children that outlived it. This is
also why `stop` and `kill` signal the whole **cgroup** rather than the
entrypoint's pid: the cgroup knows every descendant by construction.

**Fix**

```bash
minicontainer rm --force web                          # SIGKILLs everything first
cat /sys/fs/cgroup/minicontainer/<id>/cgroup.procs    # who is still in there
```

---

## The container has an IP address but no connectivity

**Symptom**

`ip addr` inside the container looks right; nothing routes.

**Cause — usually one of two**

1. `net.ipv4.ip_forward` is 0. The bridge cannot route between the container
   subnet and anywhere else. MiniContainer warns about this at launch.
2. The host's `FORWARD` chain defaults to DROP. Masquerading alone is not
   enough; the FORWARD rules have to permit the traffic, which
   `configure_nat` adds.

**Fix**

```bash
sysctl -w net.ipv4.ip_forward=1
iptables -L FORWARD -n -v          # is our ACCEPT rule present?
iptables -t nat -L POSTROUTING -n  # is the MASQUERADE rule present?
```

**On WSL2 there is a third possibility**: inbound from Windows. The WSL VM is
itself behind a NAT, so publishing a port with `-p` configures only the Linux
half. MiniContainer prints the `netsh interface portproxy` command you must
run on the Windows side. See `docs/networking.md`.

---

## `pivot_root` fails with EINVAL

**Symptom**

```
minicontainer: container process: Failed to pivot into container root
filesystem: Invalid argument (EINVAL)
```

**Cause**

`pivot_root` requires `new_root` to be a **mount point**. A plain directory is
not one. That is why setup bind-mounts the rootfs onto itself first
(`step_bind_rootfs`) — the bind is what turns a directory into a mount point.

EINVAL here also occurs when the mount namespace's propagation is still
shared, which `step_make_root_private` handles.

If you see this, one of those two steps was skipped or failed silently, which
is a bug worth reporting.

---

## Exit codes: what they mean

Distinguishing "the feature does not exist" from "the operation failed" is
deliberate, and scripts can rely on it.

| Code | Meaning |
|---|---|
| 0 | Success |
| 1 | The operation was attempted and failed |
| 2 | The command line or configuration was rejected |
| 3 | The host kernel cannot do what was asked |
| 90 | Recognised and parsed, but not implemented yet |
| 128+n | The container's entrypoint was killed by signal n |

A container that exits non-zero is **not** a MiniContainer failure: `run`
forwards the entrypoint's own status, so codes 1–127 out of a successful `run`
belong to the guest process.

```bash
minicontainer run --rootfs ~/rootfs /bin/sh -c 'exit 42'; echo $?   # 42
```

---

## `logs` says there is no captured output

**Symptom**

```
minicontainer: container web has no captured output. Only a detached
container (`run -d`) is captured; an attached run writes straight to your
terminal
```

**Cause**

By design, not a failure. An attached `run` inherits your terminal — capturing
that into a file you would then have to go and read would be worse, not
better. Only `run -d` has a file to replay.

---

## Getting more detail out of a failure

```bash
minicontainer --log-level debug run ...
MINICONTAINER_LOG=trace minicontainer run ...
```

`--log-level` beats the environment variable. Debug level reports each setup
step as it runs, which narrows a child-side failure to the exact step.

To inspect a running container from the host:

```bash
minicontainer inspect web                 # pid, cgroup, network
ls -l /proc/<pid>/ns/                     # its namespace handles
nsenter -t <pid> -a /bin/sh               # a shell inside it, bypassing our exec
```

---

## Reporting something not listed here

Include the output of `scripts/check-environment.sh` — it probes 16 host
capabilities and its table often explains an environment-specific failure by
itself — plus the failing command run with `--log-level debug`.
