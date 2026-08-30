// SPDX-License-Identifier: MIT
//
// MiniContainer - rendering container state for humans and for scripts.
//
// These are deliberately free functions taking a ContainerState rather than
// methods on Runtime. Formatting has no business touching the state store, and
// keeping it separate means every one of these can be unit-tested by
// constructing a struct - no root, no state directory, no running container.
//
// TWO AUDIENCES, TWO FORMATS
// --------------------------
// The table form is aligned and abbreviated for someone reading a terminal;
// the --json form is complete and stable for something parsing it. Trying to
// serve both with one format produces output that is awkward to read and
// annoying to parse, so they are simply separate.
#include <time.h>

#include <cstddef>
#include <cstdio>
#include <string>
#include <utility>
#include <vector>

#include "minicontainer/config.h"
#include "minicontainer/json.h"
#include "minicontainer/runtime.h"

namespace mc {

namespace {

// Pads to `width`, or returns the string unchanged when it is already longer -
// truncating a name to keep columns aligned would hide which container the row
// is about, which defeats the point of the column.
std::string pad(const std::string& s, std::size_t width) {
  if (s.size() >= width) {
    return s + " ";
  }
  return s + std::string(width - s.size(), ' ');
}

// Parses the subset of ISO-8601 this project writes: always UTC, always
// "YYYY-MM-DDTHH:MM:SS.mmmZ". A general parser would be much larger and would
// only ever see this one shape.
bool parse_iso8601(const std::string& text, ::time_t& out) {
  struct ::tm tm {};
  int millis = 0;
  if (std::sscanf(text.c_str(), "%4d-%2d-%2dT%2d:%2d:%2d.%3dZ", &tm.tm_year,
                  &tm.tm_mon, &tm.tm_mday, &tm.tm_hour, &tm.tm_min, &tm.tm_sec,
                  &millis) != 7) {
    return false;
  }
  tm.tm_year -= 1900;
  tm.tm_mon -= 1;
  // timegm, not mktime: the timestamp is UTC, and mktime would interpret it as
  // local time and silently shift it by the machine's offset.
  out = ::timegm(&tm);
  return true;
}

std::string plural(long n, const char* unit) {
  std::string s = std::to_string(n) + " " + unit;
  if (n != 1) {
    s += "s";
  }
  return s + " ago";
}

}  // namespace

std::string format_relative_time(const std::string& iso8601) {
  ::time_t then = 0;
  if (iso8601.empty() || !parse_iso8601(iso8601, then)) {
    return "unknown";
  }
  const ::time_t now = ::time(nullptr);
  long delta = static_cast<long>(now - then);

  // A small negative delta means clock skew rather than a container from the
  // future; "just now" is more useful than a negative duration.
  if (delta < 0) {
    delta = 0;
  }
  if (delta < 10) {
    return "just now";
  }
  if (delta < 60) {
    return plural(delta, "second");
  }
  if (delta < 3600) {
    return plural(delta / 60, "minute");
  }
  if (delta < 86400) {
    return plural(delta / 3600, "hour");
  }
  return plural(delta / 86400, "day");
}

std::string format_ps_table(const std::vector<ContainerState>& states) {
  if (states.empty()) {
    // An explicit message rather than bare headers: an empty table looks like
    // something failed, whereas this says plainly that nothing is there.
    return "No containers. Start one with `minicontainer run --rootfs PATH "
           "CMD`.\n";
  }

  std::string out;
  out += pad("CONTAINER ID", 14) + pad("NAME", 20) + pad("STATUS", 12) +
         pad("PID", 8) + "CREATED\n";

  for (const ContainerState& s : states) {
    // The short id is the first 12 hex characters, the same convention docker
    // uses - a full id is rarely needed and would dominate the row.
    const std::string short_id = s.id.substr(0, 12);
    const std::string pid =
        s.status == ContainerStatus::Running ? std::to_string(s.pid) : "-";

    std::string status = container_status_name(s.status);
    if (s.status == ContainerStatus::Stopped && s.term_signal != 0) {
      status += "(" + std::to_string(s.term_signal) + ")";
    } else if (s.status == ContainerStatus::Stopped && s.exit_code != 0) {
      status += "(" + std::to_string(s.exit_code) + ")";
    }

    out += pad(short_id, 14) + pad(s.name, 20) + pad(status, 12) + pad(pid, 8) +
           format_relative_time(s.created_at) + "\n";
  }
  return out;
}

std::string format_inspect(const ContainerState& state, bool json) {
  if (json) {
    return state.to_json().dump(2) + "\n";
  }

  std::string out;
  out += "Id:        " + state.id + "\n";
  out += "Name:      " + state.name + "\n";
  out +=
      "Status:    " + std::string(container_status_name(state.status)) + "\n";
  if (state.status == ContainerStatus::Running) {
    out += "Pid:       " + std::to_string(state.pid) + "\n";
  }
  out += "Created:   " + state.created_at + " (" +
         format_relative_time(state.created_at) + ")\n";
  if (!state.started_at.empty()) {
    out += "Started:   " + state.started_at + "\n";
  }
  if (!state.finished_at.empty()) {
    out += "Finished:  " + state.finished_at + "\n";
    if (state.term_signal != 0) {
      out += "Killed by: signal " + std::to_string(state.term_signal) + "\n";
    } else {
      out += "Exit code: " + std::to_string(state.exit_code) + "\n";
    }
  }

  out += "\nConfiguration\n";
  out += "  Rootfs:    " + state.config.rootfs_path + "\n";
  out += "  Hostname:  " + state.config.hostname + "\n";
  out += "  Workdir:   " + state.config.working_dir + "\n";
  out += "  Command:   ";
  for (std::size_t i = 0; i < state.config.args.size(); ++i) {
    if (i > 0) {
      out += " ";
    }
    out += state.config.args[i];
  }
  out += "\n";

  const Resources& r = state.config.resources;
  if (r.memory_bytes || r.cpus || r.pids_max || r.cpuset_cpus) {
    out += "\nResources\n";
    if (r.memory_bytes) {
      out += "  Memory:    " + format_memory_size(*r.memory_bytes) + "\n";
    }
    if (r.cpus) {
      char buf[32];
      std::snprintf(buf, sizeof(buf), "%.2f", *r.cpus);
      out += "  CPUs:      " + std::string(buf) + "\n";
    }
    if (r.pids_max) {
      out += "  Pids max:  " + std::to_string(*r.pids_max) + "\n";
    }
    if (r.cpuset_cpus) {
      out += "  Cpuset:    " + *r.cpuset_cpus + "\n";
    }
  } else {
    out += "\nResources: none set (no cgroup was created)\n";
  }

  out += "\nNetwork\n";
  out += "  Mode:      " +
         std::string(network_mode_name(state.config.network.mode)) + "\n";
  if (!state.network.ip_cidr.empty()) {
    out += "  Address:   " + state.network.ip_cidr + "\n";
    out += "  Gateway:   " + state.network.gateway + "\n";
    out += "  Bridge:    " + state.network.bridge + "\n";
    out += "  Host veth: " + state.network.veth_host + "\n";
  }
  for (const PortMapping& p : state.network.published) {
    out += "  Published: " + std::to_string(p.host_port) + " -> " +
           std::to_string(p.container_port) + "/" + p.protocol + "\n";
  }

  if (!state.cgroup_path.empty()) {
    out += "\nCgroup:    " + state.cgroup_path + "\n";
  }
  return out;
}

std::string format_stats(const ContainerState& state, const CgroupStats& stats,
                         bool json) {
  if (json) {
    JsonObject o;
    o["id"] = Json(state.id);
    o["name"] = Json(state.name);
    o["memory_current"] = Json(stats.memory_current);
    if (stats.memory_peak) {
      o["memory_peak"] = Json(*stats.memory_peak);
    }
    if (stats.memory_max) {
      o["memory_max"] = Json(*stats.memory_max);
    }
    o["cpu_usage_usec"] = Json(stats.cpu_usage_usec);
    o["pids_current"] = Json(stats.pids_current);
    if (stats.pids_max) {
      o["pids_max"] = Json(*stats.pids_max);
    }
    return Json(std::move(o)).dump(2) + "\n";
  }

  std::string out;
  out += pad("NAME", 20) + pad("MEMORY", 24) + pad("CPU", 12) + "PIDS\n";

  std::string mem = format_memory_size(stats.memory_current);
  if (stats.memory_max) {
    mem += " / " + format_memory_size(*stats.memory_max);
  } else {
    // "unlimited" rather than an empty column: a blank there reads as missing
    // data instead of as the absence of a limit.
    mem += " / unlimited";
  }

  // Microseconds are what the kernel reports; seconds are what a human wants.
  char cpu[32];
  std::snprintf(cpu, sizeof(cpu), "%.2fs",
                static_cast<double>(stats.cpu_usage_usec) / 1000000.0);

  std::string pids = std::to_string(stats.pids_current);
  if (stats.pids_max) {
    pids += " / " + std::to_string(*stats.pids_max);
  }

  out += pad(state.name, 20) + pad(mem, 24) + pad(cpu, 12) + pids + "\n";
  return out;
}

}  // namespace mc
