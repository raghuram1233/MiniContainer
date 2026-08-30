// SPDX-License-Identifier: MIT
//
// MiniContainer - building the ChildContext.
//
// This file is the boundary between "code that may allocate" and "code that
// may not". Everything here runs in the parent, before clone(), and allocates
// freely. Its entire job is to reduce a ContainerConfig - full of std::string
// and std::vector - into the flat, pointer-stable ChildContext the child can
// read without ever touching the allocator.
//
// WHY AN ARENA AND NOT JUST POINTERS INTO THE CONFIG
// --------------------------------------------------
// Pointing ChildContext at the ContainerConfig's std::string buffers would
// work right up until the config is copied, moved, or goes out of scope - and
// the child would then read freed memory with no way to detect it. Copying
// every string into one fixed buffer owned by the ChildContext itself makes
// the context self-contained: it can be moved, stored, and handed across
// clone() with no lifetime coupling to anything else.
//
// Pointers into the arena stay valid in the child because clone() without
// CLONE_VM gives it a copy-on-write address space at the SAME addresses.
#include <sched.h>

#include <cstring>
#include <string>

#include "minicontainer/container.h"
#include "minicontainer/errors.h"
#include "minicontainer/security.h"

namespace mc {

char* arena_put(ChildContext& ctx, const char* text) noexcept {
  if (text == nullptr) {
    return nullptr;
  }
  const std::size_t len = std::strlen(text);
  // +1 for the NUL. The child uses these as C strings and has no length to
  // consult, so an unterminated entry would read off the end of the arena.
  if (ctx.arena_used + len + 1 > kArenaSize) {
    return nullptr;
  }
  char* dst = ctx.arena + ctx.arena_used;
  std::memcpy(dst, text, len);
  dst[len] = '\0';
  ctx.arena_used += len + 1;
  return dst;
}

namespace {

// Every arena_put in the builder funnels through this, so a single exhausted
// arena produces one clear error naming what did not fit rather than a
// nullptr that surfaces much later as an inexplicable child-side failure.
Expected<char*> put_or_fail(ChildContext& ctx, const std::string& text,
                            const char* what) {
  char* p = arena_put(ctx, text.c_str());
  if (p == nullptr) {
    return Err(Error::invalid(
        Op::ValidateConfig,
        std::string("container configuration is too large: ran out of string "
                    "space while storing ") +
            what));
  }
  return p;
}

}  // namespace

std::uint64_t clone_flags_for(const ContainerConfig& config) noexcept {
  // PID, mount, UTS and IPC are unconditional: they are what makes this a
  // container rather than a process with a funny root directory.
  std::uint64_t flags =
      CLONE_NEWPID | CLONE_NEWNS | CLONE_NEWUTS | CLONE_NEWIPC;

  // Host networking deliberately means "no network namespace at all", not "a
  // namespace that happens to share addresses" - there is no way to express
  // the latter, and pretending otherwise would misstate the isolation.
  if (config.network.mode != NetworkMode::Host) {
    flags |= CLONE_NEWNET;
  }

  if (config.security.userns) {
    flags |= CLONE_NEWUSER;
  }

  // A pidfd is always worth having: signalling by raw pid races pid reuse,
  // and the cost of asking for one is a single field.
  flags |= CLONE_PIDFD;
  return flags;
}

Expected<void> build_child_context(const ContainerConfig& config,
                                   ChildContext& out) {
  // --- capacities, checked up front so the user gets one clear message
  // rather than a silently truncated container that misbehaves later ---
  if (config.args.empty()) {
    return Err(Error::invalid(Op::ValidateConfig,
                              "container has no entrypoint: args is empty"));
  }
  if (config.args.size() > kMaxArgs) {
    return Err(Error::invalid(
        Op::ValidateConfig, "too many arguments (" +
                                std::to_string(config.args.size()) +
                                "); the limit is " + std::to_string(kMaxArgs)));
  }
  if (config.env.size() > kMaxEnv) {
    return Err(Error::invalid(
        Op::ValidateConfig, "too many environment entries (" +
                                std::to_string(config.env.size()) +
                                "); the limit is " + std::to_string(kMaxEnv)));
  }
  if (config.bind_mounts.size() > kMaxBindMounts) {
    return Err(Error::invalid(
        Op::ValidateConfig,
        "too many bind mounts (" + std::to_string(config.bind_mounts.size()) +
            "); the limit is " + std::to_string(kMaxBindMounts)));
  }

  // --- identity ---
  out.rootfs = MC_TRY(put_or_fail(out, config.rootfs_path, "the rootfs path"));

  // No hostname means nothing to set; leaving this null is how the step knows
  // to skip, rather than needing a separate flag.
  if (!config.hostname.empty()) {
    out.hostname = MC_TRY(put_or_fail(out, config.hostname, "the hostname"));
  }

  const std::string workdir =
      config.working_dir.empty() ? std::string("/") : config.working_dir;
  out.working_dir = MC_TRY(put_or_fail(out, workdir, "the working directory"));

  // --- execve payload ---
  for (std::size_t i = 0; i < config.args.size(); ++i) {
    out.argv[i] = MC_TRY(put_or_fail(out, config.args[i], "an argument"));
  }
  out.argv[config.args.size()] = nullptr;

  for (std::size_t i = 0; i < config.env.size(); ++i) {
    out.envp[i] =
        MC_TRY(put_or_fail(out, config.env[i], "an environment entry"));
  }
  out.envp[config.env.size()] = nullptr;

  // --- bind mounts: "src:dst" or "src:dst:ro" ---
  out.bind_count = 0;
  for (const std::string& spec : config.bind_mounts) {
    const std::size_t first = spec.find(':');
    if (first == std::string::npos) {
      return Err(Error::invalid(
          Op::ValidateConfig,
          "bind mount '" + spec + "' is not in src:dst[:ro] form (no ':')"));
    }
    const std::string source = spec.substr(0, first);
    const std::size_t second = spec.find(':', first + 1);

    std::string target;
    bool read_only = false;
    if (second == std::string::npos) {
      target = spec.substr(first + 1);
    } else {
      target = spec.substr(first + 1, second - first - 1);
      const std::string mode = spec.substr(second + 1);
      if (mode == "ro") {
        read_only = true;
      } else if (mode != "rw") {
        return Err(Error::invalid(
            Op::ValidateConfig, "bind mount '" + spec + "' has mode '" + mode +
                                    "'; expected 'ro' or 'rw'"));
      }
    }
    if (source.empty() || target.empty()) {
      return Err(Error::invalid(
          Op::ValidateConfig,
          "bind mount '" + spec + "' has an empty source or target"));
    }
    if (target[0] != '/') {
      return Err(Error::invalid(Op::ValidateConfig,
                                "bind mount target '" + target +
                                    "' must be absolute inside the container"));
    }

    BindMountSpec& b = out.binds[out.bind_count];
    b.source = MC_TRY(put_or_fail(out, source, "a bind mount source"));
    b.target = MC_TRY(put_or_fail(out, target, "a bind mount target"));
    b.read_only = read_only;
    ++out.bind_count;
  }

  // --- filesystem toggles ---
  out.readonly_rootfs = config.security.readonly_rootfs;
  out.mount_sys = true;
  out.mount_devpts = true;

  // --- security ---
  // Name-to-bit resolution allocates, so it happens here and the child only
  // ever sees the resulting mask.
  out.cap_keep_mask = MC_TRY(resolve_capability_mask(config.security));
  out.drop_capabilities = !config.security.privileged;
  out.no_new_privs = config.security.no_new_privs;

  // A user namespace maps container root onto an unprivileged host uid, so
  // inside one we can stay uid 0 harmlessly. Without a user namespace,
  // container root IS host root, and dropping privileges would be the only
  // thing standing between the two - but doing that unasked would break every
  // image whose entrypoint expects to be root. So this stays off by default
  // and userns remains the supported way to not be host root.
  out.switch_user = false;
  out.uid = 0;
  out.gid = 0;

  // Compiling a seccomp profile allocates too; the child installs raw BPF.
  MC_CHECK(build_seccomp_program(config.security, out));

  return Ok();
}

}  // namespace mc
