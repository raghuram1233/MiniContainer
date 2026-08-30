// SPDX-License-Identifier: MIT
//
// MiniContainer - Tier 0 foundation: thin syscall wrappers and flag decoding.
//
// The formatters here are what make error messages diagnosable. When clone3()
// fails with EPERM you need to see WHICH namespace flag the kernel objected to,
// not the integer 0x7C020000.
//
// Every function here is either PURE (the formatters) or a one-line syscall
// wrapper. Both are unit-testable without root, which is deliberate: flag
// decoding bugs are silent, and would otherwise only surface inside a
// privileged integration test that is awkward to run.
#pragma once

#include <sys/types.h>

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

#include "minicontainer/errors.h"

namespace mc {

// "CLONE_NEWPID|CLONE_NEWUTS|CLONE_NEWNS" for the corresponding bitmask.
// Unknown bits render as "0x<hex>" so nothing is ever silently dropped.
std::string format_clone_flags(std::uint64_t flags);

// "MS_NOSUID|MS_NODEV|MS_RDONLY"
std::string format_mount_flags(unsigned long flags);

// "SIGTERM" for 15; "SIG<n>" for anything unnamed.
std::string format_signal(int sig);

// Maps "CLONE_NEWPID" back to the bit. Used by the OCI-style config parser,
// which names namespaces as strings.
Expected<std::uint64_t> clone_flag_from_name(std::string_view name);

// ---------------------------------------------------------------------------
// Small filesystem helpers. These exist so the ~40 places that read or write a
// one-line kernel file (cgroup attributes, uid_map, /proc/sys entries) all
// produce the same rich Error instead of each inventing its own.
// ---------------------------------------------------------------------------

// Reads an entire file. Kernel pseudo-files report st_size == 0, so this reads
// until EOF rather than trusting stat().
Expected<std::string> read_file(const std::string& path, Op op = Op::ReadFile);

// A single write() of the whole buffer. cgroup and procfs attribute files
// reject partial writes, so this deliberately does NOT loop on a short write -
// there, a short write is a real error rather than something to retry.
Expected<void> write_file(const std::string& path, std::string_view content,
                          Op op = Op::WriteFile);

// mkdir -p. Succeeds when the directory already exists.
Expected<void> make_directories(const std::string& path,
                                Op op = Op::CreateDirectory);

// Atomic replace: write <path>.tmp.<pid>, fsync, rename(2). Used for state.json
// so a crash mid-write can never leave a truncated state file behind.
Expected<void> write_file_atomic(const std::string& path,
                                 std::string_view content,
                                 Op op = Op::WriteState);

bool is_directory(const std::string& path) noexcept;
bool path_exists(const std::string& path) noexcept;

// Resolves to an absolute, symlink-free path. Makes rootfs validation resistant
// to symlink swaps before we ever bind-mount the result.
Expected<std::string> canonicalize(const std::string& path,
                                   Op op = Op::ValidateRootfs);

}  // namespace mc
