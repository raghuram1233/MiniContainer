// SPDX-License-Identifier: MIT
//
// MiniContainer - process layer: RAII file descriptor and pipe primitives.
// See include/minicontainer/process.h for the contract.

#include <fcntl.h>
#include <unistd.h>

#include <optional>
#include <utility>

#include "minicontainer/errors.h"
#include "minicontainer/process.h"

namespace mc {

Fd& Fd::operator=(Fd&& other) noexcept {
  if (this != &other) {
    // reset(new_fd) closes whatever we currently hold, then adopts the
    // moved-from fd. other.release() sets other's fd_ to -1 so its destructor
    // is a no-op.
    reset(other.release());
  }
  return *this;
}

void Fd::reset(int fd) noexcept {
  // close(2) never leaves the fd open on Linux, even when it returns -1/EINTR
  // (the descriptor slot is released regardless; EINTR there just means the
  // *device's* flush may not have finished). Retrying close() after EINTR is
  // therefore not merely unnecessary but actively wrong: the fd number may
  // already have been reused by another thread's open(), and a retry would
  // close that unrelated fd instead.
  if (fd_ >= 0) {
    ::close(fd_);
  }
  fd_ = fd;
}

Expected<Fd> Fd::duplicate() const {
  if (fd_ < 0) {
    return Err(
        Error::invalid(Op::Internal, "duplicate() called on an invalid fd"));
  }
  int nfd = ::fcntl(fd_, F_DUPFD_CLOEXEC, 0);
  if (nfd < 0) {
    return Err(Error::syscall(Op::Internal, "fcntl", errno, "F_DUPFD_CLOEXEC"));
  }
  return Fd(nfd);
}

Expected<Pipe> Pipe::create() {
  int fds[2] = {-1, -1};
  if (::pipe2(fds, O_CLOEXEC) < 0) {
    return Err(Error::syscall(Op::CreatePipe, "pipe2", errno, "O_CLOEXEC"));
  }
  Pipe p;
  p.read_end = Fd(fds[0]);
  p.write_end = Fd(fds[1]);
  return p;
}

Expected<std::optional<char>> Pipe::read_byte() {
  for (;;) {
    char c = 0;
    ssize_t n = ::read(read_end.get(), &c, 1);
    if (n < 0) {
      if (errno == EINTR)
        continue;
      return Err(Error::syscall(Op::SyncHandshake, "read", errno, ""));
    }
    if (n == 0) {
      // Writer closed its end: EOF, not an error. This is the success signal
      // in the execve()-closes-the-CLOEXEC-pipe handshake described in
      // process.h.
      return std::optional<char>(std::nullopt);
    }
    return std::optional<char>(c);
  }
}

Expected<void> Pipe::write_byte(char c) {
  for (;;) {
    ssize_t n = ::write(write_end.get(), &c, 1);
    if (n < 0) {
      if (errno == EINTR)
        continue;
      return Err(Error::syscall(Op::SyncHandshake, "write", errno, ""));
    }
    return Ok();
  }
}

}  // namespace mc
