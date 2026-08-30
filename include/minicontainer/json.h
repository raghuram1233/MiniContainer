// SPDX-License-Identifier: MIT
//
// MiniContainer - a minimal JSON value, writer, and parser.
//
// WHY NOT A LIBRARY
// -----------------
// state.json is the only JSON this project reads or writes, its schema is
// ours, and it is never fed untrusted input from the network. Pulling in
// nlohmann/json for that would add a large dependency to a project whose point
// is that you can read all of it. This is deliberately the smallest thing that
// round-trips our own schema correctly.
//
// It is NOT a general-purpose JSON implementation: no \u escape decoding
// beyond the basics, no big-number handling, no duplicate-key policy. It is
// strict about what it accepts and reports a byte offset on failure, which is
// what makes a corrupted state file diagnosable rather than mysterious.
#pragma once

#include <cstdint>
#include <map>
#include <string>
#include <string_view>
#include <vector>

#include "minicontainer/errors.h"

namespace mc {

class Json;
using JsonObject = std::map<std::string, Json>;
using JsonArray = std::vector<Json>;

class Json {
 public:
  enum class Type { Null, Bool, Number, String, Array, Object };

  Json() = default;
  Json(bool b);
  Json(double n);
  Json(std::int64_t n);
  Json(std::uint64_t n);
  Json(int n);
  Json(const char* s);
  Json(std::string s);
  Json(JsonArray a);
  Json(JsonObject o);

  [[nodiscard]] Type type() const noexcept { return type_; }
  [[nodiscard]] bool is_null() const noexcept { return type_ == Type::Null; }

  // Typed accessors. Each returns the fallback when the value is absent or of
  // the wrong type, so reading a state file written by an older version
  // degrades rather than aborting.
  [[nodiscard]] bool as_bool(bool fallback = false) const noexcept;
  [[nodiscard]] double as_number(double fallback = 0) const noexcept;
  [[nodiscard]] std::int64_t as_int(std::int64_t fallback = 0) const noexcept;
  [[nodiscard]] std::uint64_t as_uint(
      std::uint64_t fallback = 0) const noexcept;
  [[nodiscard]] const std::string& as_string() const noexcept;
  [[nodiscard]] const JsonArray& as_array() const noexcept;
  [[nodiscard]] const JsonObject& as_object() const noexcept;

  // Object member lookup. Returns a null Json when absent, so chains like
  // j["network"]["ip_cidr"].as_string() never throw on a partial file.
  [[nodiscard]] const Json& operator[](const std::string& key) const noexcept;
  [[nodiscard]] bool contains(const std::string& key) const noexcept;

  JsonObject& object();  // for building
  JsonArray& array();

  // An `indent` of 0 emits a single line; 2 pretty-prints, which is what
  // state.json uses so a human debugging a container can just cat it.
  [[nodiscard]] std::string dump(int indent = 0) const;

 private:
  Type type_ = Type::Null;
  bool bool_ = false;
  double num_ = 0;
  std::string str_;
  JsonArray arr_;
  JsonObject obj_;
};

// Parses `text`. On failure the Error's detail names the byte offset and what
// was expected there.
Expected<Json> json_parse(std::string_view text, Op op = Op::ReadState);

// Escapes a string as a JSON string literal, including the surrounding quotes.
std::string json_escape(std::string_view s);

}  // namespace mc
