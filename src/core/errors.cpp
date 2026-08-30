// SPDX-License-Identifier: MIT
//
// MiniContainer - Tier 0 foundation: error model, Expected, rollback ledger.
// Implementation. See include/minicontainer/errors.h for the contract.

#include "minicontainer/errors.h"

#include <unistd.h>

#include <cstdlib>
#include <cstring>

#include "minicontainer/logging.h"

namespace mc {

// ---------------------------------------------------------------------------
// op_description / op_name - driven by the MC_OP_LIST X-macro so they can
// never drift from the Op enum.
// ---------------------------------------------------------------------------
const char* op_description(Op op) noexcept {
  switch (op) {
#define MC_OP_DESC_CASE(name, desc) \
  case Op::name:                    \
    return desc;
    MC_OP_LIST(MC_OP_DESC_CASE)
#undef MC_OP_DESC_CASE
  }
  return "perform unknown operation";
}

const char* op_name(Op op) noexcept {
  switch (op) {
#define MC_OP_NAME_CASE(name, desc) \
  case Op::name:                    \
    return #name;
    MC_OP_LIST(MC_OP_NAME_CASE)
#undef MC_OP_NAME_CASE
  }
  return "Unknown";
}

// ---------------------------------------------------------------------------
// errno_name - a linear table, not a switch: several errno macros (notably
// ENOTSUP / EOPNOTSUPP) alias to the same integer value on Linux, which would
// make a switch statement ill-formed (duplicate case labels).
// ---------------------------------------------------------------------------
namespace {
struct ErrnoEntry {
  int value;
  const char* name;
};

// clang-format off
constexpr ErrnoEntry kErrnoTable[] = {
    {EPERM, "EPERM"},
    {EACCES, "EACCES"},
    {ENOENT, "ENOENT"},
    {EEXIST, "EEXIST"},
    {EINVAL, "EINVAL"},
    {ENOSPC, "ENOSPC"},
    {EBUSY, "EBUSY"},
    {ENOTDIR, "ENOTDIR"},
    {EISDIR, "EISDIR"},
    {ENOMEM, "ENOMEM"},
    {EAGAIN, "EAGAIN"},
    {ECHILD, "ECHILD"},
    {ESRCH, "ESRCH"},
    {EMFILE, "EMFILE"},
    {ENFILE, "ENFILE"},
    {EXDEV, "EXDEV"},
    {ELOOP, "ELOOP"},
    {ENAMETOOLONG, "ENAMETOOLONG"},
    {ENOSYS, "ENOSYS"},
    {EOPNOTSUPP, "EOPNOTSUPP"},
    {EUSERS, "EUSERS"},
    {ENOTSUP, "ENOTSUP"},
    {EROFS, "EROFS"},
    {EMLINK, "EMLINK"},
    {ERANGE, "ERANGE"},
    {EDOM, "EDOM"},
    {EPIPE, "EPIPE"},
    {EINTR, "EINTR"},
};
// clang-format on
}  // namespace

const char* errno_name(int err) noexcept {
  if (err == 0)
    return "";
  for (const auto& entry : kErrnoTable) {
    if (entry.value == err)
      return entry.name;
  }
  return "";
}

// ---------------------------------------------------------------------------
// Error factories.
// ---------------------------------------------------------------------------
Error Error::syscall(Op op, std::string_view name, int errnum,
                     std::string detail) {
  Error e;
  e.op_ = op;
  e.err_ = errnum;
  e.syscall_ = std::string(name);
  e.detail_ = std::move(detail);
  return e;
}

Error Error::invalid(Op op, std::string what) {
  Error e;
  e.op_ = op;
  e.detail_ = std::move(what);
  return e;
}

Error Error::unsupported(Op op, std::string what) {
  Error e;
  e.op_ = op;
  e.detail_ = std::move(what);
  return e;
}

Error Error::from_child(const ChildErrorWire& wire) {
  Error e;
  e.op_ = static_cast<Op>(wire.op);
  e.err_ = wire.err;
  e.from_child_ = true;
  std::uint16_t len = wire.detail_len;
  if (len > sizeof(wire.detail))
    len = static_cast<std::uint16_t>(sizeof(wire.detail));
  e.detail_.assign(wire.detail, len);
  return e;
}

// ---------------------------------------------------------------------------
// message() - the single user-facing rendering.
// ---------------------------------------------------------------------------
std::string Error::message() const {
  std::string msg;
  if (from_child_)
    msg += "container process: ";

  msg += "Failed to ";
  msg += op_description(op_);

  if (!syscall_.empty()) {
    msg += ": ";
    msg += syscall_;
    if (!detail_.empty()) {
      msg += "(";
      msg += detail_;
      msg += ")";
    }
  } else if (!detail_.empty()) {
    msg += ": ";
    msg += detail_;
  }

  if (err_ != 0) {
    msg += ": ";
    msg += std::strerror(err_);
    const char* en = errno_name(err_);
    if (en != nullptr && en[0] != '\0') {
      msg += " (";
      msg += en;
      msg += ")";
    }
  }

  if (!context_.empty()) {
    msg += " [";
    msg += context_;
    msg += "]";
  }

  return msg;
}

Error& Error::with_context(std::string ctx) & {
  if (ctx.empty())
    return *this;
  if (context_.empty()) {
    context_ = std::move(ctx);
  } else {
    context_ += "; ";
    context_ += ctx;
  }
  return *this;
}

Error&& Error::with_context(std::string ctx) && {
  with_context(std::move(ctx));
  return std::move(*this);
}

// ---------------------------------------------------------------------------
// expected_access_violation - programmer error, not a runtime failure.
// Deliberately avoids std::ostream/iostream machinery so it stays cheap and
// predictable even if called in a weird state; it is not required to be
// async-signal-safe (it is a parent-side / test-side abort), but there is no
// reason to make it heavier than necessary.
// ---------------------------------------------------------------------------
[[noreturn]] void expected_access_violation(
    const char* what, const std::string& detail) noexcept {
  auto raw_write = [](const char* s, std::size_t len) {
    (void)::write(2, s, len);
  };
  static const char kPrefix[] = "minicontainer: fatal: Expected<>::";
  static const char kMid[] = " accessed incorrectly: ";
  static const char kNl[] = "\n";
  raw_write(kPrefix, sizeof(kPrefix) - 1);
  raw_write(what, std::strlen(what));
  raw_write(kMid, sizeof(kMid) - 1);
  raw_write(detail.c_str(), detail.size());
  raw_write(kNl, sizeof(kNl) - 1);
  std::abort();
}

// ---------------------------------------------------------------------------
// Rollback.
// ---------------------------------------------------------------------------
void Rollback::push(std::string what, std::function<void()> undo) {
  actions_.push_back(Action{std::move(what), std::move(undo)});
}

void Rollback::run() noexcept {
  for (auto it = actions_.rbegin(); it != actions_.rend(); ++it) {
    if (!it->undo)
      continue;
    try {
      it->undo();
    } catch (const std::exception& e) {
      MC_LOG_WARN("rollback: failed to undo " << it->what << ": " << e.what());
    } catch (...) {
      MC_LOG_WARN("rollback: failed to undo " << it->what
                                              << ": unknown exception");
    }
  }
  actions_.clear();
}

}  // namespace mc
