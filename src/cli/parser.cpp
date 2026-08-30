// SPDX-License-Identifier: MIT
//
// MiniContainer - CLI: argv -> ParsedCommand.
//
// This file is the entire parsing surface. It never creates a namespace,
// touches a cgroup, or makes a privileged syscall - it only turns strings
// into a validated mc::ContainerConfig plus a chosen Command. That is what
// lets tests/unit/test_cli.cpp exercise every rule below without root.
//
// THE ONE BUG THIS FILE IS WRITTEN TO AVOID
// ------------------------------------------
// For `run`/`create`/`exec`, our own flags may only appear BEFORE the
// container's command. The moment we see the first token that is not one of
// our recognised flags, flag-scanning stops for good and every remaining
// token - even ones spelled like flags, e.g. `ls -la` - is copied verbatim
// into the container's argv. See parse_run_or_create() and parse_exec().
#include <cctype>
#include <charconv>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

#include "minicontainer/cli.h"

namespace mc {
namespace {

// ---------------------------------------------------------------------------
// Small string/number helpers. No exceptions, no allocation surprises.
// ---------------------------------------------------------------------------

int levenshtein(std::string_view a, std::string_view b) {
  std::vector<std::vector<int>> dp(a.size() + 1,
                                   std::vector<int>(b.size() + 1, 0));
  for (std::size_t i = 0; i <= a.size(); ++i)
    dp[i][0] = static_cast<int>(i);
  for (std::size_t j = 0; j <= b.size(); ++j)
    dp[0][j] = static_cast<int>(j);
  for (std::size_t i = 1; i <= a.size(); ++i) {
    for (std::size_t j = 1; j <= b.size(); ++j) {
      int cost = (a[i - 1] == b[j - 1]) ? 0 : 1;
      int del = dp[i - 1][j] + 1;
      int ins = dp[i][j - 1] + 1;
      int sub = dp[i - 1][j - 1] + cost;
      int best = del < ins ? del : ins;
      dp[i][j] = best < sub ? best : sub;
    }
  }
  return dp[a.size()][b.size()];
}

std::optional<std::string> closest_match(
    const std::string& tok, const std::vector<std::string>& candidates) {
  std::optional<std::string> best;
  int best_dist = 1000000;
  for (const auto& c : candidates) {
    int d = levenshtein(tok, c);
    if (d < best_dist) {
      best_dist = d;
      best = c;
    }
  }
  if (best && best_dist <= 3)
    return best;
  return std::nullopt;
}

Error unknown_flag_error(const std::string& tok,
                         const std::vector<std::string>& candidates) {
  std::string msg = "unknown flag '" + tok + "'";
  if (auto m = closest_match(tok, candidates)) {
    msg += "; did you mean '" + *m + "'?";
  }
  return Error::invalid(Op::ParseArgs, std::move(msg));
}

bool looks_like_flag(const std::string& tok) {
  return tok.size() >= 2 && tok[0] == '-';
}

struct LongFlag {
  std::string name;
  std::optional<std::string> inline_value;
};

// Splits "--foo=bar" into {"--foo", "bar"}; "--foo" into {"--foo", nullopt}.
LongFlag split_long(const std::string& tok) {
  auto pos = tok.find('=');
  if (pos == std::string::npos)
    return {tok, std::nullopt};
  return {tok.substr(0, pos), tok.substr(pos + 1)};
}

// Resolves a flag's value: the inline "=value" if present, else the next
// token in `rest` (advancing `i` to consume it). `display` is the flag's
// name as it should appear in an error message, e.g. "--memory" or
// "-e/--env".
Expected<std::string> take_value(const std::vector<std::string>& rest,
                                 std::size_t& i,
                                 const std::optional<std::string>& inline_value,
                                 const std::string& display) {
  if (inline_value)
    return *inline_value;
  if (i + 1 >= rest.size()) {
    return Err(Error::invalid(Op::ParseArgs,
                              "flag '" + display + "' expects a value"));
  }
  ++i;
  return rest[i];
}

std::string to_lower(std::string_view s) {
  std::string out;
  out.reserve(s.size());
  for (char c : s)
    out.push_back(
        static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
  return out;
}

std::string to_upper(std::string_view s) {
  std::string out;
  out.reserve(s.size());
  for (char c : s)
    out.push_back(
        static_cast<char>(std::toupper(static_cast<unsigned char>(c))));
  return out;
}

Expected<std::uint64_t> parse_u64_field(const std::string& text,
                                        const std::string& flag) {
  std::uint64_t v = 0;
  auto res = std::from_chars(text.data(), text.data() + text.size(), v);
  if (res.ec != std::errc() || res.ptr != text.data() + text.size()) {
    return Err(Error::invalid(
        Op::ParseArgs, "flag '" + flag +
                           "' expects a non-negative integer, got '" + text +
                           "'"));
  }
  return v;
}

Expected<int> parse_int_field(const std::string& text,
                              const std::string& flag) {
  int v = 0;
  auto res = std::from_chars(text.data(), text.data() + text.size(), v);
  if (res.ec != std::errc() || res.ptr != text.data() + text.size()) {
    return Err(Error::invalid(
        Op::ParseArgs,
        "flag '" + flag + "' expects an integer, got '" + text + "'"));
  }
  return v;
}

Expected<double> parse_double_field(const std::string& text,
                                    const std::string& flag) {
  double v = 0;
  auto res = std::from_chars(text.data(), text.data() + text.size(), v);
  if (res.ec != std::errc() || res.ptr != text.data() + text.size()) {
    return Err(Error::invalid(
        Op::ParseArgs,
        "flag '" + flag + "' expects a number, got '" + text + "'"));
  }
  return v;
}

Expected<bool> parse_bool_field(const std::string& text,
                                const std::string& flag) {
  std::string lower = to_lower(text);
  if (lower == "true" || lower == "1" || lower == "yes")
    return true;
  if (lower == "false" || lower == "0" || lower == "no")
    return false;
  return Err(Error::invalid(
      Op::ParseArgs,
      "flag '" + flag + "' expects true or false, got '" + text + "'"));
}

Expected<std::uint64_t> parse_memory_field(const std::string& text,
                                           const std::string& flag) {
  auto r = parse_memory_size(text);
  if (!r) {
    return Err(Error::invalid(
        Op::ParseArgs, "flag '" + flag + "' has an invalid value '" + text +
                           "': " + r.error().message()));
  }
  return r.value();
}

Expected<PortMapping> parse_port_field(const std::string& text) {
  auto r = parse_port_mapping(text);
  if (!r) {
    return Err(Error::invalid(
        Op::ParseArgs, "flag '-p/--publish' has an invalid value '" + text +
                           "': " + r.error().message()));
  }
  return r.value();
}

Expected<NetworkMode> parse_network_field(const std::string& text) {
  std::string lower = to_lower(text);
  if (lower != "none" && lower != "bridge" && lower != "host") {
    return Err(Error::invalid(
        Op::ParseArgs,
        "flag '--network' expects one of: none, bridge, host; got '" + text +
            "'"));
  }
  return network_mode_from_string(text);
}

Expected<int> parse_signal_field(const std::string& text) {
  if (text.empty()) {
    return Err(
        Error::invalid(Op::ParseArgs, "flag '--signal' expects a value"));
  }
  if (std::isdigit(static_cast<unsigned char>(text[0]))) {
    auto v = parse_int_field(text, "--signal");
    if (!v)
      return Err(std::move(v).error());
    return *v;
  }
  std::string upper = to_upper(text);
  if (upper.rfind("SIG", 0) == 0)
    upper = upper.substr(3);
  static const std::unordered_map<std::string, int> kTable = {
      {"HUP", SIGHUP},       {"INT", SIGINT},   {"QUIT", SIGQUIT},
      {"ILL", SIGILL},       {"TRAP", SIGTRAP}, {"ABRT", SIGABRT},
      {"BUS", SIGBUS},       {"FPE", SIGFPE},   {"KILL", SIGKILL},
      {"USR1", SIGUSR1},     {"SEGV", SIGSEGV}, {"USR2", SIGUSR2},
      {"PIPE", SIGPIPE},     {"ALRM", SIGALRM}, {"TERM", SIGTERM},
      {"CHLD", SIGCHLD},     {"CONT", SIGCONT}, {"STOP", SIGSTOP},
      {"TSTP", SIGTSTP},     {"TTIN", SIGTTIN}, {"TTOU", SIGTTOU},
      {"URG", SIGURG},       {"XCPU", SIGXCPU}, {"XFSZ", SIGXFSZ},
      {"VTALRM", SIGVTALRM}, {"PROF", SIGPROF}, {"WINCH", SIGWINCH},
      {"IO", SIGIO},         {"PWR", SIGPWR},   {"SYS", SIGSYS},
  };
  auto it = kTable.find(upper);
  if (it == kTable.end()) {
    return Err(Error::invalid(
        Op::ParseArgs,
        "unknown signal '" + text +
            "'; expected a number or a name like TERM, KILL, HUP"));
  }
  return it->second;
}

// ---------------------------------------------------------------------------
// run / create - the flag set is identical; only the Command differs.
// ---------------------------------------------------------------------------
const std::vector<std::string>& run_long_flags() {
  static const std::vector<std::string> kFlags = {
      "--name",         "--hostname", "--rootfs",      "--memory",
      "--memory-swap",  "--cpus",     "--cpu-shares",  "--pids",
      "--cpuset-cpus",  "--network",  "--ip",          "--dns",
      "--publish",      "--cap-add",  "--cap-drop",    "--seccomp",
      "--no-new-privs", "--userns",   "--privileged",  "--read-only",
      "--env",          "--workdir",  "--volume",      "--tty",
      "--detach",       "--rm",       "--interactive", "--help",
  };
  return kFlags;
}

Expected<ParsedCommand> parse_run_or_create(
    Command cmd, const std::vector<std::string>& rest) {
  ParsedCommand pc;
  pc.command = cmd;
  bool rootfs_set = false;
  bool dns_set = false;
  std::size_t i = 0;

  for (; i < rest.size(); ++i) {
    const std::string& tok = rest[i];

    if (tok == "--") {
      ++i;
      break;
    }
    if (!looks_like_flag(tok))
      break;  // first non-flag token: the tail begins here
    if (tok == "-h" || tok == "--help") {
      ParsedCommand help_pc;
      help_pc.command = Command::Help;
      help_pc.target = command_name(cmd);
      return help_pc;
    }

    if (tok.size() >= 2 && tok[1] == '-') {
      LongFlag lf = split_long(tok);
      const std::string& name = lf.name;

      if (name == "--name") {
        auto v = take_value(rest, i, lf.inline_value, name);
        if (!v)
          return Err(std::move(v).error());
        pc.config.name = *v;
      } else if (name == "--hostname") {
        auto v = take_value(rest, i, lf.inline_value, name);
        if (!v)
          return Err(std::move(v).error());
        pc.config.hostname = *v;
      } else if (name == "--rootfs") {
        auto v = take_value(rest, i, lf.inline_value, name);
        if (!v)
          return Err(std::move(v).error());
        pc.config.rootfs_path = *v;
        rootfs_set = true;
      } else if (name == "--memory") {
        auto v = take_value(rest, i, lf.inline_value, name);
        if (!v)
          return Err(std::move(v).error());
        auto mv = parse_memory_field(*v, name);
        if (!mv)
          return Err(std::move(mv).error());
        pc.config.resources.memory_bytes = *mv;
      } else if (name == "--memory-swap") {
        auto v = take_value(rest, i, lf.inline_value, name);
        if (!v)
          return Err(std::move(v).error());
        auto mv = parse_memory_field(*v, name);
        if (!mv)
          return Err(std::move(mv).error());
        pc.config.resources.memory_swap_bytes = *mv;
      } else if (name == "--cpus") {
        auto v = take_value(rest, i, lf.inline_value, name);
        if (!v)
          return Err(std::move(v).error());
        auto dv = parse_double_field(*v, name);
        if (!dv)
          return Err(std::move(dv).error());
        pc.config.resources.cpus = *dv;
      } else if (name == "--cpu-shares") {
        auto v = take_value(rest, i, lf.inline_value, name);
        if (!v)
          return Err(std::move(v).error());
        auto uv = parse_u64_field(*v, name);
        if (!uv)
          return Err(std::move(uv).error());
        pc.config.resources.cpu_shares = *uv;
      } else if (name == "--pids") {
        auto v = take_value(rest, i, lf.inline_value, name);
        if (!v)
          return Err(std::move(v).error());
        auto uv = parse_u64_field(*v, name);
        if (!uv)
          return Err(std::move(uv).error());
        pc.config.resources.pids_max = *uv;
      } else if (name == "--cpuset-cpus") {
        auto v = take_value(rest, i, lf.inline_value, name);
        if (!v)
          return Err(std::move(v).error());
        pc.config.resources.cpuset_cpus = *v;
      } else if (name == "--network") {
        auto v = take_value(rest, i, lf.inline_value, name);
        if (!v)
          return Err(std::move(v).error());
        auto nv = parse_network_field(*v);
        if (!nv)
          return Err(std::move(nv).error());
        pc.config.network.mode = *nv;
      } else if (name == "--ip") {
        auto v = take_value(rest, i, lf.inline_value, name);
        if (!v)
          return Err(std::move(v).error());
        pc.config.network.container_ip = *v;
      } else if (name == "--dns") {
        auto v = take_value(rest, i, lf.inline_value, name);
        if (!v)
          return Err(std::move(v).error());
        if (!dns_set) {
          pc.config.network.dns_servers.clear();
          dns_set = true;
        }
        pc.config.network.dns_servers.push_back(*v);
      } else if (name == "--publish") {
        auto v = take_value(rest, i, lf.inline_value, name);
        if (!v)
          return Err(std::move(v).error());
        auto pv = parse_port_field(*v);
        if (!pv)
          return Err(std::move(pv).error());
        pc.config.network.ports.push_back(*pv);
      } else if (name == "--cap-add") {
        auto v = take_value(rest, i, lf.inline_value, name);
        if (!v)
          return Err(std::move(v).error());
        pc.config.security.cap_add.push_back(*v);
      } else if (name == "--cap-drop") {
        auto v = take_value(rest, i, lf.inline_value, name);
        if (!v)
          return Err(std::move(v).error());
        pc.config.security.cap_drop.push_back(*v);
      } else if (name == "--seccomp") {
        auto v = take_value(rest, i, lf.inline_value, name);
        if (!v)
          return Err(std::move(v).error());
        if (*v == "off") {
          pc.config.security.seccomp = SeccompMode::Off;
        } else if (*v == "default") {
          pc.config.security.seccomp = SeccompMode::Default;
        } else {
          pc.config.security.seccomp = SeccompMode::Profile;
          pc.config.security.seccomp_profile_path = *v;
        }
      } else if (name == "--no-new-privs") {
        if (lf.inline_value) {
          auto bv = parse_bool_field(*lf.inline_value, name);
          if (!bv)
            return Err(std::move(bv).error());
          pc.config.security.no_new_privs = *bv;
        } else {
          pc.config.security.no_new_privs = true;
        }
      } else if (name == "--userns") {
        pc.config.security.userns = true;
      } else if (name == "--privileged") {
        pc.config.security.privileged = true;
      } else if (name == "--read-only") {
        pc.config.security.readonly_rootfs = true;
      } else if (name == "--env") {
        auto v = take_value(rest, i, lf.inline_value, name);
        if (!v)
          return Err(std::move(v).error());
        pc.config.env.push_back(*v);
      } else if (name == "--workdir") {
        auto v = take_value(rest, i, lf.inline_value, name);
        if (!v)
          return Err(std::move(v).error());
        pc.config.working_dir = *v;
      } else if (name == "--volume") {
        auto v = take_value(rest, i, lf.inline_value, name);
        if (!v)
          return Err(std::move(v).error());
        pc.config.bind_mounts.push_back(*v);
      } else if (name == "--tty") {
        pc.config.tty = true;
      } else if (name == "--detach") {
        pc.config.detach = true;
      } else if (name == "--rm") {
        pc.config.remove_on_exit = true;
      } else if (name == "--interactive") {
        pc.interactive = true;
      } else {
        return Err(unknown_flag_error(name, run_long_flags()));
      }
      continue;
    }

    // Short flag(s). -p/-e/-w/-v take a value (possibly attached, "-eK=V");
    // everything else may be clustered, e.g. "-it" == "-i -t".
    char c0 = tok[1];
    if (c0 == 'p' || c0 == 'e' || c0 == 'w' || c0 == 'v') {
      std::optional<std::string> inline_val =
          tok.size() > 2 ? std::optional<std::string>(tok.substr(2))
                         : std::nullopt;
      const char* display = c0 == 'p'   ? "-p/--publish"
                            : c0 == 'e' ? "-e/--env"
                            : c0 == 'w' ? "-w/--workdir"
                                        : "-v/--volume";
      auto v = take_value(rest, i, inline_val, display);
      if (!v)
        return Err(std::move(v).error());
      if (c0 == 'p') {
        auto pv = parse_port_field(*v);
        if (!pv)
          return Err(std::move(pv).error());
        pc.config.network.ports.push_back(*pv);
      } else if (c0 == 'e') {
        pc.config.env.push_back(*v);
      } else if (c0 == 'w') {
        pc.config.working_dir = *v;
      } else {
        pc.config.bind_mounts.push_back(*v);
      }
    } else {
      for (std::size_t k = 1; k < tok.size(); ++k) {
        char c = tok[k];
        if (c == 't') {
          pc.config.tty = true;
        } else if (c == 'd') {
          pc.config.detach = true;
        } else if (c == 'i') {
          pc.interactive = true;
        } else if (c == 'h') {
          ParsedCommand help_pc;
          help_pc.command = Command::Help;
          help_pc.target = command_name(cmd);
          return help_pc;
        } else {
          return Err(
              unknown_flag_error(std::string("-") + c, run_long_flags()));
        }
      }
    }
  }

  std::vector<std::string> tail(rest.begin() + static_cast<std::ptrdiff_t>(i),
                                rest.end());
  const std::string cmd_name = command_name(cmd);
  if (rootfs_set) {
    if (tail.empty()) {
      return Err(Error::invalid(Op::ParseArgs,
                                cmd_name +
                                    " requires a command after --rootfs, e.g. "
                                    "`minicontainer " +
                                    cmd_name + " --rootfs ./rootfs /bin/sh`"));
    }
    pc.config.args = tail;
  } else {
    if (tail.empty()) {
      return Err(Error::invalid(Op::ParseArgs,
                                cmd_name + " requires either --rootfs PATH CMD "
                                           "[ARGS...] or a bundle directory"));
    }
    pc.bundle_path = tail[0];
    if (tail.size() > 1)
      pc.config.args.assign(tail.begin() + 1, tail.end());
  }

  pc.config.apply_defaults();
  auto validated = pc.config.validate();
  if (!validated)
    return Err(std::move(validated).error());
  return pc;
}

// ---------------------------------------------------------------------------
// start / stop / kill / ps / inspect / stats / logs / rm - flags may appear
// in any order around a single optional-or-required positional NAME.
// ---------------------------------------------------------------------------

Expected<ParsedCommand> parse_start(const std::vector<std::string>& rest) {
  ParsedCommand pc;
  pc.command = Command::Start;
  static const std::vector<std::string> kFlags = {"--help"};
  for (std::size_t i = 0; i < rest.size(); ++i) {
    const std::string& tok = rest[i];
    if (tok == "-h" || tok == "--help") {
      pc.command = Command::Help;
      pc.target = "start";
      return pc;
    }
    if (looks_like_flag(tok))
      return Err(unknown_flag_error(tok, kFlags));
    if (!pc.target.empty()) {
      return Err(
          Error::invalid(Op::ParseArgs, "unexpected argument '" + tok + "'"));
    }
    pc.target = tok;
  }
  if (pc.target.empty()) {
    return Err(Error::invalid(Op::ParseArgs,
                              "start requires a container name, e.g. "
                              "`minicontainer start mycontainer`"));
  }
  return pc;
}

Expected<ParsedCommand> parse_stop(const std::vector<std::string>& rest) {
  ParsedCommand pc;
  pc.command = Command::Stop;
  static const std::vector<std::string> kFlags = {"--time", "--help"};
  for (std::size_t i = 0; i < rest.size(); ++i) {
    const std::string& tok = rest[i];
    if (tok == "-h" || tok == "--help") {
      pc.command = Command::Help;
      pc.target = "stop";
      return pc;
    }
    if (looks_like_flag(tok)) {
      LongFlag lf = split_long(tok);
      if (lf.name == "--time") {
        auto v = take_value(rest, i, lf.inline_value, "--time");
        if (!v)
          return Err(std::move(v).error());
        auto iv = parse_int_field(*v, "--time");
        if (!iv)
          return Err(std::move(iv).error());
        pc.stop_timeout_sec = *iv;
      } else {
        return Err(unknown_flag_error(tok, kFlags));
      }
      continue;
    }
    if (!pc.target.empty()) {
      return Err(
          Error::invalid(Op::ParseArgs, "unexpected argument '" + tok + "'"));
    }
    pc.target = tok;
  }
  if (pc.target.empty()) {
    return Err(Error::invalid(Op::ParseArgs,
                              "stop requires a container name, e.g. "
                              "`minicontainer stop mycontainer`"));
  }
  return pc;
}

Expected<ParsedCommand> parse_kill(const std::vector<std::string>& rest) {
  ParsedCommand pc;
  pc.command = Command::Kill;
  static const std::vector<std::string> kFlags = {"--signal", "--help"};
  for (std::size_t i = 0; i < rest.size(); ++i) {
    const std::string& tok = rest[i];
    if (tok == "-h" || tok == "--help") {
      pc.command = Command::Help;
      pc.target = "kill";
      return pc;
    }
    if (looks_like_flag(tok)) {
      LongFlag lf = split_long(tok);
      if (lf.name == "--signal") {
        auto v = take_value(rest, i, lf.inline_value, "--signal");
        if (!v)
          return Err(std::move(v).error());
        auto sv = parse_signal_field(*v);
        if (!sv)
          return Err(std::move(sv).error());
        pc.signal = *sv;
      } else {
        return Err(unknown_flag_error(tok, kFlags));
      }
      continue;
    }
    if (!pc.target.empty()) {
      return Err(
          Error::invalid(Op::ParseArgs, "unexpected argument '" + tok + "'"));
    }
    pc.target = tok;
  }
  if (pc.target.empty()) {
    return Err(Error::invalid(Op::ParseArgs,
                              "kill requires a container name, e.g. "
                              "`minicontainer kill mycontainer`"));
  }
  return pc;
}

Expected<ParsedCommand> parse_ps(const std::vector<std::string>& rest) {
  ParsedCommand pc;
  pc.command = Command::Ps;
  static const std::vector<std::string> kFlags = {"--all", "--json", "--help"};
  for (const std::string& tok : rest) {
    if (tok == "-h" || tok == "--help") {
      pc.command = Command::Help;
      pc.target = "ps";
      return pc;
    }
    if (tok == "-a" || tok == "--all") {
      pc.all = true;
      continue;
    }
    if (tok == "--json") {
      pc.json = true;
      continue;
    }
    if (looks_like_flag(tok))
      return Err(unknown_flag_error(tok, kFlags));
    return Err(Error::invalid(
        Op::ParseArgs, "ps does not take a positional argument ('" + tok +
                           "'); did you mean --all or --json?"));
  }
  return pc;
}

Expected<ParsedCommand> parse_inspect(const std::vector<std::string>& rest) {
  ParsedCommand pc;
  pc.command = Command::Inspect;
  static const std::vector<std::string> kFlags = {"--json", "--help"};
  for (const std::string& tok : rest) {
    if (tok == "-h" || tok == "--help") {
      pc.command = Command::Help;
      pc.target = "inspect";
      return pc;
    }
    if (tok == "--json") {
      pc.json = true;
      continue;
    }
    if (looks_like_flag(tok))
      return Err(unknown_flag_error(tok, kFlags));
    if (!pc.target.empty()) {
      return Err(
          Error::invalid(Op::ParseArgs, "unexpected argument '" + tok + "'"));
    }
    pc.target = tok;
  }
  if (pc.target.empty()) {
    return Err(Error::invalid(Op::ParseArgs,
                              "inspect requires a container name, e.g. "
                              "`minicontainer inspect mycontainer`"));
  }
  return pc;
}

Expected<ParsedCommand> parse_stats(const std::vector<std::string>& rest) {
  ParsedCommand pc;
  pc.command = Command::Stats;
  static const std::vector<std::string> kFlags = {"--no-stream", "--help"};
  for (const std::string& tok : rest) {
    if (tok == "-h" || tok == "--help") {
      pc.command = Command::Help;
      pc.target = "stats";
      return pc;
    }
    if (tok == "--no-stream") {
      pc.no_stream = true;
      continue;
    }
    if (looks_like_flag(tok))
      return Err(unknown_flag_error(tok, kFlags));
    if (!pc.target.empty()) {
      return Err(
          Error::invalid(Op::ParseArgs, "unexpected argument '" + tok + "'"));
    }
    pc.target = tok;
  }
  return pc;  // NAME is optional
}

Expected<ParsedCommand> parse_logs(const std::vector<std::string>& rest) {
  ParsedCommand pc;
  pc.command = Command::Logs;
  static const std::vector<std::string> kFlags = {"--follow", "--help"};
  for (const std::string& tok : rest) {
    if (tok == "-h" || tok == "--help") {
      pc.command = Command::Help;
      pc.target = "logs";
      return pc;
    }
    if (tok == "-f" || tok == "--follow") {
      pc.follow = true;
      continue;
    }
    if (looks_like_flag(tok))
      return Err(unknown_flag_error(tok, kFlags));
    if (!pc.target.empty()) {
      return Err(
          Error::invalid(Op::ParseArgs, "unexpected argument '" + tok + "'"));
    }
    pc.target = tok;
  }
  if (pc.target.empty()) {
    return Err(Error::invalid(Op::ParseArgs,
                              "logs requires a container name, e.g. "
                              "`minicontainer logs mycontainer`"));
  }
  return pc;
}

Expected<ParsedCommand> parse_rm(const std::vector<std::string>& rest) {
  ParsedCommand pc;
  pc.command = Command::Rm;
  static const std::vector<std::string> kFlags = {"--force", "--help"};
  for (const std::string& tok : rest) {
    if (tok == "-h" || tok == "--help") {
      pc.command = Command::Help;
      pc.target = "rm";
      return pc;
    }
    if (tok == "-f" || tok == "--force") {
      pc.force = true;
      continue;
    }
    if (looks_like_flag(tok))
      return Err(unknown_flag_error(tok, kFlags));
    if (!pc.target.empty()) {
      return Err(
          Error::invalid(Op::ParseArgs, "unexpected argument '" + tok + "'"));
    }
    pc.target = tok;
  }
  if (pc.target.empty()) {
    return Err(Error::invalid(
        Op::ParseArgs,
        "rm requires a container name, e.g. `minicontainer rm mycontainer`"));
  }
  return pc;
}

// ---------------------------------------------------------------------------
// exec - flags first, then NAME, then the container's own command verbatim.
// Same "first non-flag stops us" rule as run/create.
// ---------------------------------------------------------------------------
Expected<ParsedCommand> parse_exec(const std::vector<std::string>& rest) {
  ParsedCommand pc;
  pc.command = Command::Exec;
  static const std::vector<std::string> kFlags = {"--env", "--workdir", "--tty",
                                                  "--help"};
  std::size_t i = 0;

  for (; i < rest.size(); ++i) {
    const std::string& tok = rest[i];
    if (tok == "--") {
      ++i;
      break;
    }
    if (!looks_like_flag(tok))
      break;  // NAME begins here
    if (tok == "-h" || tok == "--help") {
      pc.command = Command::Help;
      pc.target = "exec";
      return pc;
    }

    if (tok.size() >= 2 && tok[1] == '-') {
      LongFlag lf = split_long(tok);
      if (lf.name == "--env") {
        auto v = take_value(rest, i, lf.inline_value, lf.name);
        if (!v)
          return Err(std::move(v).error());
        pc.exec_env.push_back(*v);
      } else if (lf.name == "--workdir") {
        auto v = take_value(rest, i, lf.inline_value, lf.name);
        if (!v)
          return Err(std::move(v).error());
        pc.exec_workdir = *v;
      } else if (lf.name == "--tty") {
        pc.exec_tty = true;
      } else {
        return Err(unknown_flag_error(lf.name, kFlags));
      }
      continue;
    }

    char c0 = tok[1];
    if (c0 == 'e' || c0 == 'w') {
      std::optional<std::string> inline_val =
          tok.size() > 2 ? std::optional<std::string>(tok.substr(2))
                         : std::nullopt;
      const char* display = c0 == 'e' ? "-e/--env" : "-w/--workdir";
      auto v = take_value(rest, i, inline_val, display);
      if (!v)
        return Err(std::move(v).error());
      if (c0 == 'e') {
        pc.exec_env.push_back(*v);
      } else {
        pc.exec_workdir = *v;
      }
    } else {
      for (std::size_t k = 1; k < tok.size(); ++k) {
        char c = tok[k];
        if (c == 't') {
          pc.exec_tty = true;
        } else if (c == 'h') {
          pc.command = Command::Help;
          pc.target = "exec";
          return pc;
        } else {
          return Err(unknown_flag_error(std::string("-") + c, kFlags));
        }
      }
    }
  }

  if (i >= rest.size()) {
    return Err(Error::invalid(Op::ParseArgs,
                              "exec requires a container name and a command, "
                              "e.g. `minicontainer exec "
                              "mycontainer /bin/sh`"));
  }
  pc.target = rest[i];
  ++i;
  if (i >= rest.size()) {
    return Err(Error::invalid(
        Op::ParseArgs, "exec requires a command to run inside '" + pc.target +
                           "', e.g. `minicontainer exec " + pc.target +
                           " /bin/sh`"));
  }
  pc.exec_args.assign(rest.begin() + static_cast<std::ptrdiff_t>(i),
                      rest.end());
  return pc;
}

}  // namespace

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

const char* command_name(Command c) noexcept {
  switch (c) {
    case Command::Run:
      return "run";
    case Command::Create:
      return "create";
    case Command::Start:
      return "start";
    case Command::Stop:
      return "stop";
    case Command::Kill:
      return "kill";
    case Command::Exec:
      return "exec";
    case Command::Ps:
      return "ps";
    case Command::Inspect:
      return "inspect";
    case Command::Stats:
      return "stats";
    case Command::Logs:
      return "logs";
    case Command::Rm:
      return "rm";
    case Command::Version:
      return "version";
    case Command::Help:
      return "help";
  }
  return "help";
}

Expected<ParsedCommand> parse_args(const std::vector<std::string>& args) {
  std::size_t i = 0;
  ParsedCommand global;
  static const std::vector<std::string> kGlobalFlags = {"--log-level", "--help",
                                                        "--version"};

  while (i < args.size()) {
    const std::string& tok = args[i];
    if (tok == "-h" || tok == "--help") {
      global.command = Command::Help;
      return global;
    }
    if (tok == "-v" || tok == "--version") {
      global.command = Command::Version;
      return global;
    }
    if (looks_like_flag(tok)) {
      LongFlag lf = split_long(tok);
      if (lf.name == "--log-level") {
        auto v = take_value(args, i, lf.inline_value, "--log-level");
        if (!v)
          return Err(std::move(v).error());
        global.log_level = log_level_from_string(*v);
        global.log_level_set = true;
        ++i;
        continue;
      }
      return Err(unknown_flag_error(tok, kGlobalFlags));
    }
    break;
  }

  if (i >= args.size()) {
    global.command = Command::Help;
    return global;
  }

  const std::string sub = args[i++];
  std::vector<std::string> rest(args.begin() + static_cast<std::ptrdiff_t>(i),
                                args.end());

  Command cmd;
  if (sub == "run") {
    cmd = Command::Run;
  } else if (sub == "create") {
    cmd = Command::Create;
  } else if (sub == "start") {
    cmd = Command::Start;
  } else if (sub == "stop") {
    cmd = Command::Stop;
  } else if (sub == "kill") {
    cmd = Command::Kill;
  } else if (sub == "exec") {
    cmd = Command::Exec;
  } else if (sub == "ps") {
    cmd = Command::Ps;
  } else if (sub == "inspect") {
    cmd = Command::Inspect;
  } else if (sub == "stats") {
    cmd = Command::Stats;
  } else if (sub == "logs") {
    cmd = Command::Logs;
  } else if (sub == "rm") {
    cmd = Command::Rm;
  } else if (sub == "version") {
    global.command = Command::Version;
    return global;
  } else if (sub == "help") {
    global.command = Command::Help;
    if (!rest.empty())
      global.target = rest[0];
    return global;
  } else {
    static const std::vector<std::string> kCommands = {
        "run",     "create", "start", "stop", "kill",    "exec", "ps",
        "inspect", "stats",  "logs",  "rm",   "version", "help",
    };
    std::string msg = "unknown command '" + sub + "'";
    if (auto m = closest_match(sub, kCommands)) {
      msg += "; did you mean '" + *m + "'?";
    } else {
      msg +=
          "; expected one of: run, create, start, stop, kill, exec, ps, "
          "inspect, stats, logs, rm, "
          "version, help";
    }
    return Err(Error::invalid(Op::ParseArgs, std::move(msg)));
  }

  Expected<ParsedCommand> result = [&]() -> Expected<ParsedCommand> {
    switch (cmd) {
      case Command::Run:
      case Command::Create:
        return parse_run_or_create(cmd, rest);
      case Command::Start:
        return parse_start(rest);
      case Command::Stop:
        return parse_stop(rest);
      case Command::Kill:
        return parse_kill(rest);
      case Command::Exec:
        return parse_exec(rest);
      case Command::Ps:
        return parse_ps(rest);
      case Command::Inspect:
        return parse_inspect(rest);
      case Command::Stats:
        return parse_stats(rest);
      case Command::Logs:
        return parse_logs(rest);
      case Command::Rm:
        return parse_rm(rest);
      default:
        return Err(
            Error::invalid(Op::ParseArgs, "internal: unhandled command"));
    }
  }();

  if (!result)
    return result;
  ParsedCommand pc = std::move(result).value();
  if (global.log_level_set) {
    pc.log_level = global.log_level;
    pc.log_level_set = true;
  }
  return pc;
}

Expected<ParsedCommand> parse_command_line(int argc, const char* const argv[]) {
  std::vector<std::string> args;
  if (argc > 1)
    args.reserve(static_cast<std::size_t>(argc - 1));
  for (int i = 1; i < argc; ++i)
    args.emplace_back(argv[i]);
  return parse_args(args);
}

std::string usage_text() {
  return "minicontainer - a from-scratch educational Linux container runtime\n"
         "\n"
         "USAGE:\n"
         "  minicontainer [--log-level LEVEL] <command> [ARGS...]\n"
         "  minicontainer -h | --help\n"
         "  minicontainer -v | --version\n"
         "\n"
         "COMMANDS:\n"
         "  run       create and start a new container\n"
         "  create    create a container without starting it\n"
         "  start     start a created container\n"
         "  stop      gracefully stop a running container\n"
         "  kill      send a signal to a running container\n"
         "  exec      run a command inside a running container\n"
         "  ps        list containers\n"
         "  inspect   show detailed container information\n"
         "  stats     show live resource usage\n"
         "  logs      show container logs\n"
         "  rm        remove a container\n"
         "  version   print version information\n"
         "  help      show this message, or `help <command>` for command help\n"
         "\n"
         "GLOBAL FLAGS:\n"
         "  --log-level LEVEL   trace|debug|info|warn|error|off (default: "
         "info)\n"
         "  -h, --help          show help\n"
         "  -v, --version       show version\n"
         "\n"
         "Run `minicontainer help <command>` for details on a specific "
         "command.\n";
}

std::string command_usage(Command c) {
  switch (c) {
    case Command::Run:
      return "minicontainer run [FLAGS] (--rootfs PATH CMD [ARGS...] | "
             "BUNDLE_DIR)\n"
             "\n"
             "Create and start a new container, then wait for it to exit "
             "(unless -d).\n"
             "\n"
             "FLAGS:\n"
             "  --name NAME              container name\n"
             "  --hostname NAME          UTS hostname (default: container id)\n"
             "  --rootfs PATH            root filesystem directory\n"
             "  --memory SIZE            memory limit, e.g. 256M, 1G\n"
             "  --memory-swap SIZE       swap limit\n"
             "  --cpus N                 fractional CPU limit, e.g. 0.5\n"
             "  --cpu-shares N           relative CPU weight\n"
             "  --pids N                 max number of processes\n"
             "  --cpuset-cpus LIST       cpuset.cpus value, e.g. 0-3\n"
             "  --network MODE           none|bridge|host\n"
             "  --ip ADDR                static container IP (bridge mode)\n"
             "  --dns ADDR               DNS server (repeatable)\n"
             "  -p, --publish MAP        publish a port, e.g. 8080:80 or "
             "8080:80/udp (repeatable)\n"
             "  --cap-add CAP            add a Linux capability (repeatable)\n"
             "  --cap-drop CAP           drop a Linux capability (repeatable)\n"
             "  --seccomp MODE           off|default|PATH to a profile\n"
             "  --no-new-privs[=BOOL]    set no_new_privs (default: true)\n"
             "  --userns                 enable a user namespace\n"
             "  --privileged             keep all capabilities\n"
             "  --read-only              mount the root filesystem read-only\n"
             "  -e, --env KEY=VALUE      set an environment variable "
             "(repeatable)\n"
             "  -w, --workdir PATH       working directory inside the "
             "container\n"
             "  -v, --volume SRC:DST[:ro]  bind mount (repeatable)\n"
             "  -t, --tty                allocate a pseudo-TTY\n"
             "  -i, --interactive        keep stdin open\n"
             "  -d, --detach             run in the background\n"
             "  --rm                     remove the container when it exits\n"
             "  -h, --help               show this message\n"
             "\n"
             "The first non-flag argument begins the container's own command "
             "line;\n"
             "everything after it, including tokens that look like flags, is "
             "passed\n"
             "through untouched. Use `--` to separate our flags from the "
             "command\n"
             "explicitly, e.g. `minicontainer run --rootfs ./r -- /bin/sh -c "
             "\"echo hi\"`.\n";
    case Command::Create:
      return "minicontainer create [FLAGS] (--rootfs PATH CMD [ARGS...] | "
             "BUNDLE_DIR)\n"
             "\n"
             "Same flags as `run`, but only creates the container; it is not "
             "started.\n"
             "See `minicontainer help run` for the full flag list.\n";
    case Command::Start:
      return "minicontainer start NAME\n\nStart a previously created "
             "container.\n";
    case Command::Stop:
      return "minicontainer stop NAME [--time N]\n\n"
             "Ask the container to exit, then SIGKILL it after N seconds "
             "(default 10).\n";
    case Command::Kill:
      return "minicontainer kill NAME [--signal SIG]\n\n"
             "Send a signal to a running container. SIG may be numeric (9) or "
             "a name\n"
             "(TERM, KILL, HUP, ...). Default: TERM.\n";
    case Command::Exec:
      return "minicontainer exec [FLAGS] NAME CMD [ARGS...]\n\n"
             "Run a new command inside a running container's namespaces.\n"
             "\n"
             "FLAGS:\n"
             "  -e, --env KEY=VALUE   set an environment variable "
             "(repeatable)\n"
             "  -w, --workdir PATH    working directory for the new process\n"
             "  -t, --tty             allocate a pseudo-TTY\n"
             "  -h, --help            show this message\n";
    case Command::Ps:
      return "minicontainer ps [-a|--all] [--json]\n\n"
             "List containers. By default only running containers are shown.\n";
    case Command::Inspect:
      return "minicontainer inspect NAME [--json]\n\nShow detailed information "
             "about a container.\n";
    case Command::Stats:
      return "minicontainer stats [NAME] [--no-stream]\n\n"
             "Show live resource usage. Without NAME, shows all running "
             "containers.\n";
    case Command::Logs:
      return "minicontainer logs NAME [-f|--follow]\n\nShow a container's "
             "captured stdout/stderr.\n";
    case Command::Rm:
      return "minicontainer rm NAME [-f|--force]\n\nRemove a stopped "
             "container's state.\n";
    case Command::Version:
      return "minicontainer version\n\nPrint the minicontainer version and "
             "build information.\n";
    case Command::Help:
      return "minicontainer help [COMMAND]\n\n"
             "Show the top-level usage, or detailed help for COMMAND.\n";
  }
  return "";
}

}  // namespace mc
