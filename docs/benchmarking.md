# Benchmarking

Status: **Planned — methodology only. There are no numbers in this document,
and that is deliberate.**

MiniContainer can create and run containers, but it has not been benchmarked.
Publishing figures now would mean publishing figures nobody has validated, for
a runtime whose networking path is still unproven. This document specifies how
the measurement should be done, so that the numbers — when they exist — mean
something.

---

## What is worth measuring, and what is not

**Worth measuring**

| Metric | Why it is interesting |
|---|---|
| Cold start latency | `run` to the entrypoint's first instruction. The number people actually feel, and where `clone3()` vs `fork`+`unshare` would show up. |
| Teardown latency | `stop` to cgroup removed. Dominated by signal delivery, which is where the PID-1 init shim matters. |
| Steady-state overhead | CPU and memory cost of the runtime *while the container runs*. For MiniContainer this should be near zero: nothing supervises the container except an init shim blocked in `poll()`. |
| Init shim footprint | One extra process per container. Worth knowing whether that is 200KB or 2MB. |

**Not worth measuring**

Throughput of the workload inside the container. Once `execve` has happened,
the container is an ordinary process in some namespaces; its I/O and CPU
throughput are the kernel's, not the runtime's. Measuring that measures Linux,
not MiniContainer — and a "container runtime benchmark" that reports it is
usually measuring the wrong thing.

---

## The baseline problem

Comparing against Docker is the obvious idea and is **not a like-for-like
comparison**. `docker run` includes image resolution, layer mounting via
overlayfs, a daemon round-trip, and network plugin setup. MiniContainer does
none of those. A raw `docker run` vs `minicontainer run` chart would flatter
MiniContainer for work it simply does not do.

Fair comparisons, in increasing order of usefulness:

1. **`runc` directly**, not Docker. runc is the layer that actually does what
   MiniContainer does — namespaces, cgroups, pivot_root, exec — with the image
   and daemon machinery stripped out. This is the only genuinely comparable
   baseline.
2. **`docker run` with a pre-pulled image and `--network none`**, which
   removes the two largest sources of unrelated work.
3. **A bare `unshare` + `chroot` script**, as a floor: the minimum the kernel
   charges for this work, with no runtime at all.

Any published number must state which baseline it used and what was excluded.

---

## Method

**Isolate the variable.** Cold start is dominated by page-cache state and
scheduler noise. So:

- Warm up: discard the first 10 runs.
- Sample: at least 100 runs; report median and p95, not the mean. Cold-start
  distributions have a long right tail, and a mean hides it.
- Pin CPU frequency if you can (`cpupower frequency-set -g performance`). On
  WSL2 you generally cannot, which is itself worth stating in the results.
- Use the same static busybox rootfs everywhere, on ext4, page-cache warm.

**Measure the right span.** Timing `minicontainer run` from the outside
includes process startup and the parent's own teardown. To isolate container
creation, have the entrypoint report a timestamp as its first act and compare
against one taken just before `run`:

```bash
start=$(date +%s%N)
minicontainer run --rootfs ~/rootfs /bin/sh -c 'true'
end=$(date +%s%N)
echo $(( (end - start) / 1000000 ))ms
```

For a finer breakdown, `--log-level debug` reports each setup step as it runs,
which attributes cost to a specific syscall rather than to "container
creation" as a lump.

**Report the environment.** Kernel version, distro, WSL2 vs bare metal,
whether cgroup controllers were delegated, and whether the rootfs was on ext4.
A WSL2 number and a bare-metal number are not the same measurement, and
MiniContainer's development environment is WSL2.

---

## Expected shape of the results

Stated in advance, so the measurement can falsify them rather than confirm
whatever it happens to find:

- **MiniContainer should be much faster than `docker run`**, and that margin
  should be almost entirely image and daemon work, not runtime efficiency. If
  it is not, something is wrong with the comparison.
- **MiniContainer should be roughly comparable to `runc`**, within noise — it
  makes the same syscalls. If it is dramatically faster, the comparison is
  probably unfair (runc does more OCI validation); if dramatically slower,
  there is a real inefficiency worth finding.
- **`CLONE_INTO_CGROUP` should not be measurably faster** than writing
  `cgroup.procs` afterwards. Its value is correctness — no window in which the
  container runs unconfined — not speed. A benchmark claiming a speedup there
  is probably measuring noise.

---

## Prerequisites before any of this is worth running

1. Bridge networking exercised end to end, so the network path can be measured
   rather than skipped.
2. A reference `runc` installation.
3. Tests for the Wave 2 modules, so a performance change can be made without
   silently breaking correctness — optimising an untested runtime optimises
   for the wrong thing.

See the README's Status section for which of these exist today.
