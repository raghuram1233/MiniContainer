# Getting Started

MiniContainer targets Linux (namespaces, cgroups v2, `clone3()`). The
development machine for this project is a Windows 11 host, so this guide
starts from Windows and gets you to a WSL2 environment that behaves like a
real Linux box — because that constraint (and its sharp edges) is part of
what you need to understand to build this project correctly.

## 1. Install WSL2 with Ubuntu 24.04

From an elevated Windows terminal (PowerShell):

```powershell
wsl --install -d Ubuntu-24.04 --no-launch
```

`--no-launch` skips the first-run interactive user setup so you can enter
the distro as root directly:

```powershell
wsl -d Ubuntu-24.04 -u root
```

Verify you're on WSL2 (not WSL1 — WSL1 does not run a real Linux kernel and
namespaces/cgroups will not behave correctly):

```powershell
wsl -l -v
```

You want `VERSION` = 2 next to `Ubuntu-24.04`.

The development environment this project was built and documented against:
WSL2 Ubuntu 24.04.4 LTS, kernel `6.18.33.2-microsoft-standard-WSL2`, running
as root, with systemd enabled (`/etc/wsl.conf` has `[boot] systemd=true`).
systemd matters: it is what delegates `cpu memory pids` into
`cgroup.subtree_control` at boot (see `docs/cgroups.md`) — without it you
would have to do that delegation yourself.

## 2. Install the toolchain

Inside the WSL distro, as root:

```bash
apt-get update
apt-get install -y \
  build-essential g++-13 cmake ninja-build \
  libseccomp-dev libcap-dev \
  iptables iproute2 \
  pkg-config git
```

Versions this project was developed against: g++ 13.3.0, cmake 3.28.3,
ninja 1.11.1, libseccomp 2.5.5, libcap 2.66, iptables 1.8.10 (nf_tables
backend). Newer versions of these within the same major line should work;
note the libseccomp behaviour described in `src/security/seccomp.cpp` if you pull a much newer
kernel than 6.18 without a matching libseccomp.

`<expected>` is C++23 and g++ 13 does not ship it — that's why this project
has its own `mc::Expected` in `errors.h` rather than using
`std::expected`. You do not need a newer compiler; this is intentional.

## 3. Why the build tree must live in WSL's ext4, not on /mnt/c

The repository source can live on the Windows filesystem
(`/mnt/c/TRR/TRR/MiniContainer`, mounted via drvfs) — reading source files
from there is fine. But **the CMake build directory, and anything
MiniContainer creates at runtime (container rootfs, `/var/lib/minicontainer`
state), must live on a native WSL ext4 path**, such as `~/mc-build`.

Reason: drvfs is a 9p filesystem. It cannot represent Linux file mode bits
correctly, cannot hold device nodes, and its symlink semantics don't match
native Linux. `mknod()` — which MiniContainer needs to populate `/dev`
inside a container rootfs — fails outright on drvfs. Building or running
anything container-related under `/mnt/c` will produce confusing, silent-ish
failures rather than a clean error. See `docs/troubleshooting.md` for the
exact symptom.

## 4. Configure and build

```bash
mkdir -p ~/mc-build
cmake -S /mnt/c/TRR/TRR/MiniContainer -B ~/mc-build -G Ninja \
  -DCMAKE_BUILD_TYPE=Debug
cmake --build ~/mc-build
```

`-S` points at the source tree (fine on drvfs — it's read-only traffic from
CMake's perspective at configure time); `-B` is the build tree and **must**
be the `~/mc-build` ext4 path, never a path under `/mnt/c`.

As of 2026-08-30 (end of Wave 1) this produces a real `minicontainer` binary
at `~/mc-build/minicontainer`, plus `~/mc-build/tests/mc_unit_tests` and
`~/mc-build/tests/mc_integration_tests`. Check it with:

```bash
~/mc-build/minicontainer version
~/mc-build/minicontainer help run
```

The runtime is complete: `run` creates and starts a real container. See the
README's Status section for exactly what is proven end-to-end versus what is
implemented but not yet exercised (bridge networking, `exec`).

To run the tests:

```bash
# Unprivileged - the same set GitHub CI runs.
ctest --test-dir ~/mc-build --output-on-failure -LE root

# Privileged - real namespaces, needs root. WSL gives you this by default.
sudo ctest --test-dir ~/mc-build --output-on-failure -L root
```

## 5. Where runtime state will live

Once the runtime exists, its default paths (from `RuntimePaths` in
`config.h`) are:

- State: `/var/lib/minicontainer` (override with `MINICONTAINER_ROOT`)
- Cgroups: `/sys/fs/cgroup` (override with `MINICONTAINER_CGROUP_ROOT`)

Both must be WSL-native paths for the same drvfs reason as the build tree.
The env var overrides exist specifically so integration tests can redirect
every write into a scratch directory without touching the real system
paths.

## 6. Sanity-check your cgroup v2 setup

Before relying on cgroup-based limits, check what your distro has actually
delegated — do not assume:

```bash
cat /sys/fs/cgroup/cgroup.controllers
cat /sys/fs/cgroup/cgroup.subtree_control
```

On the Ubuntu-24.04 WSL distro (systemd running) this project was developed
against: `cgroup.controllers` reports `cpuset cpu io memory hugetlb pids
rdma`, and `cgroup.subtree_control` reports `cpu memory pids` — already
delegated. On the docker-desktop WSL distro, `subtree_control` is
**empty**. This is exactly why `docs/cgroups.md` insists MiniContainer must
probe this file at runtime rather than assume any controller is available.

## 7. Editor / line endings

If you edit files from Windows tools, make sure your editor is configured
for LF line endings on this repo. `.gitattributes` enforces LF for shell
scripts and CMake files; a CRLF-saved `.sh` file will fail inside WSL bash
with a `$'\r': command not found` error the first time it runs — see
`docs/troubleshooting.md`.
