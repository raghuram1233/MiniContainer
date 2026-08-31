// SPDX-License-Identifier: MIT
//
// MiniContainer - process layer: joining existing namespaces via setns(2).
// See include/minicontainer/process.h for the contract.
//
// ORDERING RULES (see process.h and repeated here at the point of use):
//   1. A user namespace must be joined BEFORE the namespaces it owns. Every
//      non-user namespace records the user namespace that was active when it
//      was created ("owning user namespace"); setns() on that namespace
//      checks the caller's capabilities against the owning user namespace, so
//      joining, say, a mount namespace before its owning user namespace can
//      leave the caller without the CAP_SYS_ADMIN the kernel expects it to
//      have there.
//   2. Joining a PID namespace affects only children created AFTER the
//      setns() call - the caller's own PID and view of /proc do not change.
//      A process that setns()s into a PID namespace and then reads its own
//      pid still sees its original pid; only a subsequent fork()/clone()
//      produces a child whose pid (and pid 1-ness) is relative to the new
//      namespace.

#include <sys/stat.h>

#include <fcntl.h>
#include <sched.h>
#include <unistd.h>

#include <string>

#include "minicontainer/errors.h"
#include "minicontainer/process.h"

#ifndef CLONE_NEWTIME
#define CLONE_NEWTIME 0x00000080
#endif

namespace mc {

const char* ns_type_name(NsType t) noexcept {
  switch (t) {
    case NsType::Pid:
      return "PID";
    case NsType::Uts:
      return "UTS";
    case NsType::Mount:
      return "Mount";
    case NsType::Ipc:
      return "IPC";
    case NsType::Net:
      return "Network";
    case NsType::User:
      return "User";
    case NsType::Cgroup:
      return "Cgroup";
    case NsType::Time:
      return "Time";
  }
  return "Unknown";
}

const char* ns_proc_name(NsType t) noexcept {
  switch (t) {
    case NsType::Pid:
      return "pid";
    case NsType::Uts:
      return "uts";
    case NsType::Mount:
      return "mnt";
    case NsType::Ipc:
      return "ipc";
    case NsType::Net:
      return "net";
    case NsType::User:
      return "user";
    case NsType::Cgroup:
      return "cgroup";
    case NsType::Time:
      return "time";
  }
  return "unknown";
}

namespace {

// Whether ns_fd refers to the SAME namespace instance as the calling
// process's own current one, per the (device, inode) pair namespaces(7)
// documents as a unique identifier for a live namespace. Returns false (never
// aborts the join) on any stat() failure, so an inability to tell defers to
// setns() itself for the real error rather than masking one.
bool same_as_current_namespace(const Fd& ns_fd, NsType type) noexcept {
  struct ::stat target_st {};
  if (::fstat(ns_fd.get(), &target_st) != 0) {
    return false;
  }
  const std::string self_path =
      std::string("/proc/self/ns/") + ns_proc_name(type);
  struct ::stat self_st {};
  if (::stat(self_path.c_str(), &self_st) != 0) {
    return false;
  }
  return target_st.st_dev == self_st.st_dev &&
         target_st.st_ino == self_st.st_ino;
}

int clone_flag_for(NsType t) noexcept {
  switch (t) {
    case NsType::Pid:
      return CLONE_NEWPID;
    case NsType::Uts:
      return CLONE_NEWUTS;
    case NsType::Mount:
      return CLONE_NEWNS;
    case NsType::Ipc:
      return CLONE_NEWIPC;
    case NsType::Net:
      return CLONE_NEWNET;
    case NsType::User:
      return CLONE_NEWUSER;
    case NsType::Cgroup:
      return CLONE_NEWCGROUP;
    case NsType::Time:
      return CLONE_NEWTIME;
  }
  return 0;
}
}  // namespace

Expected<Fd> open_namespace(::pid_t pid, NsType type) {
  std::string path =
      "/proc/" + std::to_string(pid) + "/ns/" + ns_proc_name(type);
  int fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC);
  if (fd < 0) {
    return Err(Error::syscall(Op::OpenNamespace, "open", errno, path));
  }
  return Fd(fd);
}

Expected<void> join_namespace(const Fd& ns_fd, NsType type) {
  // Joining a namespace the caller is already a member of is, semantically,
  // already done - and for the user namespace specifically the kernel
  // actively refuses the setns() call in that case (EINVAL) rather than
  // treating it as the no-op every other namespace type tolerates. A
  // container started without --userns lives in the SAME user namespace as
  // the caller (there is no separate one to join, since SecurityConfig::userns
  // defaults to false), which is the common case - so without this check,
  // `exec` failed against every ordinary container and only worked against
  // ones that had opted into a user namespace.
  if (same_as_current_namespace(ns_fd, type)) {
    return Ok();
  }
  if (::setns(ns_fd.get(), clone_flag_for(type)) < 0) {
    return Err(
        Error::syscall(Op::JoinNamespace, "setns", errno, ns_type_name(type)));
  }
  return Ok();
}

}  // namespace mc
