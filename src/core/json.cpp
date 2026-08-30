// SPDX-License-Identifier: MIT
//
// MiniContainer - a minimal JSON value, writer, and parser.
// Implementation. See include/minicontainer/json.h for the contract.
//
// THE TRAPS THIS FILE EXISTS TO AVOID
// -----------------------------------
// 1. Non-deterministic output. state.json is rewritten on every lifecycle
//    transition; if key order wandered, every write would be a large diff and
//    "what actually changed" would be unanswerable. Objects are std::map, so
//    dump() is sorted and stable by construction.
//
// 2. Integers acquiring a fractional tail. Numbers are stored as double, but a
//    pid written as "1234.0" is not an integer to any other reader (including
//    jq -e and our own as_int callers who expect an exact value). dump_number
//    therefore prints integral doubles through an integer formatter. Doubles
//    represent integers exactly to 2^53, which covers every pid, timestamp,
//    and byte count we persist.
//
// 3. Silent truncation. A state file that has been half-written or hand-edited
//    must fail loudly with a byte offset, not parse into a plausible-looking
//    value. The parser is strict: no trailing garbage, no unterminated
//    literals, and every failure names the offset and what was expected there.
//
// Accessors never throw. Reading a state file written by an older version of
// the runtime should degrade to defaults rather than abort a teardown that is
// the only thing standing between the host and a leaked cgroup.

#include "minicontainer/json.h"

#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <utility>

namespace mc {

// ---------------------------------------------------------------------------
// Construction
// ---------------------------------------------------------------------------
Json::Json(bool b) : type_(Type::Bool), bool_(b) {}
Json::Json(double n) : type_(Type::Number), num_(n) {}
Json::Json(std::int64_t n)
    : type_(Type::Number), num_(static_cast<double>(n)) {}
Json::Json(std::uint64_t n)
    : type_(Type::Number), num_(static_cast<double>(n)) {}
Json::Json(int n) : type_(Type::Number), num_(static_cast<double>(n)) {}
Json::Json(const char* s)
    : type_(Type::String),
      str_(s == nullptr ? std::string() : std::string(s)) {}
Json::Json(std::string s) : type_(Type::String), str_(std::move(s)) {}
Json::Json(JsonArray a) : type_(Type::Array), arr_(std::move(a)) {}
Json::Json(JsonObject o) : type_(Type::Object), obj_(std::move(o)) {}

// ---------------------------------------------------------------------------
// Accessors. Every one of these returns the fallback on a type mismatch; none
// of them signals an error, because the callers are teardown paths that must
// keep going.
// ---------------------------------------------------------------------------
bool Json::as_bool(bool fallback) const noexcept {
  return type_ == Type::Bool ? bool_ : fallback;
}

double Json::as_number(double fallback) const noexcept {
  return type_ == Type::Number ? num_ : fallback;
}

std::int64_t Json::as_int(std::int64_t fallback) const noexcept {
  if (type_ != Type::Number)
    return fallback;
  // Casting a double that does not fit the integer range is undefined
  // behaviour, not a wrap. A corrupt state file holding "pid": 1e300 produced
  // 0 on one toolchain - and pid 0 means "my whole process group" to kill(2),
  // so the UB was one step away from signalling the wrong processes. These
  // accessors promise never to throw and to degrade to the fallback; that
  // promise has to cover this case too.
  if (!(num_ >= -9223372036854775808.0) || !(num_ < 9223372036854775808.0))
    return fallback;
  return static_cast<std::int64_t>(num_);
}

std::uint64_t Json::as_uint(std::uint64_t fallback) const noexcept {
  if (type_ != Type::Number)
    return fallback;
  // A negative number is not a uint; casting it would wrap to something
  // enormous, which as a memory limit would be actively dangerous.
  if (num_ < 0)
    return fallback;
  // The upper end is the same undefined-behaviour trap as as_int(): a double
  // above UINT64_MAX cannot be cast, and NaN fails every comparison, which is
  // why this is written as a negated range test rather than num_ > limit.
  if (!(num_ < 18446744073709551616.0))
    return fallback;
  return static_cast<std::uint64_t>(num_);
}

const std::string& Json::as_string() const noexcept {
  static const std::string kEmpty;
  return type_ == Type::String ? str_ : kEmpty;
}

const JsonArray& Json::as_array() const noexcept {
  static const JsonArray kEmpty;
  return type_ == Type::Array ? arr_ : kEmpty;
}

const JsonObject& Json::as_object() const noexcept {
  static const JsonObject kEmpty;
  return type_ == Type::Object ? obj_ : kEmpty;
}

const Json& Json::operator[](const std::string& key) const noexcept {
  static const Json kNull;
  if (type_ != Type::Object)
    return kNull;
  auto it = obj_.find(key);
  return it == obj_.end() ? kNull : it->second;
}

bool Json::contains(const std::string& key) const noexcept {
  return type_ == Type::Object && obj_.find(key) != obj_.end();
}

JsonObject& Json::object() {
  // Building an object out of a default-constructed Json is the common case,
  // so switching type here saves every caller a two-step dance.
  if (type_ != Type::Object) {
    type_ = Type::Object;
    obj_.clear();
  }
  return obj_;
}

JsonArray& Json::array() {
  if (type_ != Type::Array) {
    type_ = Type::Array;
    arr_.clear();
  }
  return arr_;
}

// ---------------------------------------------------------------------------
// Writing
// ---------------------------------------------------------------------------
std::string json_escape(std::string_view s) {
  std::string out;
  out.reserve(s.size() + 2);
  out.push_back('"');
  for (unsigned char c : s) {
    switch (c) {
      case '"':
        out += "\\\"";
        break;
      case '\\':
        out += "\\\\";
        break;
      case '\n':
        out += "\\n";
        break;
      case '\r':
        out += "\\r";
        break;
      case '\t':
        out += "\\t";
        break;
      case '\b':
        out += "\\b";
        break;
      case '\f':
        out += "\\f";
        break;
      default:
        if (c < 0x20) {
          // Any other control character has no short escape; \u00XX is the
          // only spelling that survives a round trip.
          char buf[8];
          std::snprintf(buf, sizeof(buf), "\\u%04x", static_cast<unsigned>(c));
          out += buf;
        } else {
          // Bytes >= 0x80 are passed through unchanged: our strings are UTF-8
          // and escaping them would only make state.json harder to read.
          out.push_back(static_cast<char>(c));
        }
        break;
    }
  }
  out.push_back('"');
  return out;
}

namespace {

// Renders a number so that an integral value never grows a ".0" tail. See the
// file header: a pid or a byte count has to come back out as an integer.
std::string dump_number(double n) {
  if (!std::isfinite(n)) {
    // JSON has no spelling for NaN or infinity. Emitting one would produce a
    // file we could not read back, so null is the honest choice.
    return "null";
  }

  double integral = 0;
  if (std::modf(n, &integral) == 0.0 && std::fabs(n) < 9007199254740992.0) {
    char buf[32];
    std::snprintf(buf, sizeof(buf), "%lld",
                  static_cast<long long>(static_cast<std::int64_t>(n)));
    return buf;
  }

  // %.17g always round-trips a double but is ugly; try the shortest form that
  // reads back identically first.
  char buf[40];
  for (int precision : {15, 16, 17}) {
    std::snprintf(buf, sizeof(buf), "%.*g", precision, n);
    if (std::strtod(buf, nullptr) == n)
      break;
  }
  return buf;
}

void dump_value(const Json& j, int indent, int depth, std::string& out);

void newline_indent(int indent, int depth, std::string& out) {
  if (indent <= 0)
    return;
  out.push_back('\n');
  out.append(static_cast<std::size_t>(indent) * static_cast<std::size_t>(depth),
             ' ');
}

void dump_value(const Json& j, int indent, int depth, std::string& out) {
  switch (j.type()) {
    case Json::Type::Null:
      out += "null";
      return;
    case Json::Type::Bool:
      out += j.as_bool() ? "true" : "false";
      return;
    case Json::Type::Number:
      out += dump_number(j.as_number());
      return;
    case Json::Type::String:
      out += json_escape(j.as_string());
      return;
    case Json::Type::Array: {
      const JsonArray& a = j.as_array();
      if (a.empty()) {
        out += "[]";
        return;
      }
      out.push_back('[');
      bool first = true;
      for (const Json& item : a) {
        if (!first)
          out.push_back(',');
        first = false;
        newline_indent(indent, depth + 1, out);
        dump_value(item, indent, depth + 1, out);
      }
      newline_indent(indent, depth, out);
      out.push_back(']');
      return;
    }
    case Json::Type::Object: {
      const JsonObject& o = j.as_object();
      if (o.empty()) {
        out += "{}";
        return;
      }
      out.push_back('{');
      bool first = true;
      for (const auto& [key, value] : o) {
        if (!first)
          out.push_back(',');
        first = false;
        newline_indent(indent, depth + 1, out);
        out += json_escape(key);
        out.push_back(':');
        if (indent > 0)
          out.push_back(' ');
        dump_value(value, indent, depth + 1, out);
      }
      newline_indent(indent, depth, out);
      out.push_back('}');
      return;
    }
  }
}

}  // namespace

std::string Json::dump(int indent) const {
  std::string out;
  dump_value(*this, indent, 0, out);
  return out;
}

// ---------------------------------------------------------------------------
// Parsing
//
// Recursive descent over a string_view, tracking the byte offset so a failure
// can point at the exact character that broke. Depth is bounded: a state file
// truncated in a pathological way (or hand-edited into "[[[[[[...") must not
// be able to overflow our stack.
// ---------------------------------------------------------------------------
namespace {

constexpr int kMaxDepth = 100;

class Parser {
 public:
  Parser(std::string_view text, Op op) : text_(text), op_(op) {}

  Expected<Json> parse_document() {
    skip_whitespace();
    Json value = MC_TRY(parse_value(0));
    skip_whitespace();
    if (pos_ != text_.size()) {
      return fail("end of input after the top-level value");
    }
    return value;
  }

 private:
  Unexpected<Error> fail(std::string_view expected) const {
    return Err(Error::invalid(op_, "JSON at byte offset " +
                                       std::to_string(pos_) + ": expected " +
                                       std::string(expected)));
  }

  Unexpected<Error> fail_at(std::size_t offset,
                            std::string_view expected) const {
    return Err(Error::invalid(op_, "JSON at byte offset " +
                                       std::to_string(offset) + ": expected " +
                                       std::string(expected)));
  }

  [[nodiscard]] bool eof() const noexcept { return pos_ >= text_.size(); }
  [[nodiscard]] char peek() const noexcept { return text_[pos_]; }

  void skip_whitespace() noexcept {
    while (pos_ < text_.size()) {
      char c = text_[pos_];
      if (c == ' ' || c == '\t' || c == '\n' || c == '\r') {
        ++pos_;
      } else {
        return;
      }
    }
  }

  Expected<Json> parse_value(int depth) {
    if (depth > kMaxDepth) {
      return fail("a less deeply nested value (depth limit " +
                  std::to_string(kMaxDepth) + " exceeded)");
    }
    if (eof())
      return fail("a value");

    switch (peek()) {
      case '{':
        return parse_object(depth);
      case '[':
        return parse_array(depth);
      case '"': {
        std::string s = MC_TRY(parse_string());
        return Json(std::move(s));
      }
      case 't':
        MC_CHECK(expect_literal("true"));
        return Json(true);
      case 'f':
        MC_CHECK(expect_literal("false"));
        return Json(false);
      case 'n':
        MC_CHECK(expect_literal("null"));
        return Json();
      default:
        return parse_number();
    }
  }

  Expected<void> expect_literal(std::string_view literal) {
    if (text_.compare(pos_, literal.size(), literal) != 0) {
      return fail(literal);
    }
    pos_ += literal.size();
    return Ok();
  }

  Expected<Json> parse_object(int depth) {
    ++pos_;  // '{'
    JsonObject obj;
    skip_whitespace();
    if (eof())
      return fail("'\"' or '}'");
    if (peek() == '}') {
      ++pos_;
      return Json(std::move(obj));
    }

    for (;;) {
      skip_whitespace();
      if (eof() || peek() != '"')
        return fail("'\"' to start an object key");
      std::string key = MC_TRY(parse_string());

      skip_whitespace();
      if (eof() || peek() != ':')
        return fail("':' after the object key");
      ++pos_;

      skip_whitespace();
      Json value = MC_TRY(parse_value(depth + 1));
      // Last key wins on a duplicate. Our own writer never emits one, and
      // rejecting it would turn a harmless hand edit into an unloadable file.
      obj[std::move(key)] = std::move(value);

      skip_whitespace();
      if (eof())
        return fail("',' or '}'");
      if (peek() == ',') {
        ++pos_;
        continue;
      }
      if (peek() == '}') {
        ++pos_;
        return Json(std::move(obj));
      }
      return fail("',' or '}'");
    }
  }

  Expected<Json> parse_array(int depth) {
    ++pos_;  // '['
    JsonArray arr;
    skip_whitespace();
    if (eof())
      return fail("a value or ']'");
    if (peek() == ']') {
      ++pos_;
      return Json(std::move(arr));
    }

    for (;;) {
      skip_whitespace();
      arr.push_back(MC_TRY(parse_value(depth + 1)));

      skip_whitespace();
      if (eof())
        return fail("',' or ']'");
      if (peek() == ',') {
        ++pos_;
        continue;
      }
      if (peek() == ']') {
        ++pos_;
        return Json(std::move(arr));
      }
      return fail("',' or ']'");
    }
  }

  // Appends `cp` to `out` as UTF-8.
  static void append_utf8(std::uint32_t cp, std::string& out) {
    if (cp < 0x80) {
      out.push_back(static_cast<char>(cp));
    } else if (cp < 0x800) {
      out.push_back(static_cast<char>(0xC0 | (cp >> 6)));
      out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    } else if (cp < 0x10000) {
      out.push_back(static_cast<char>(0xE0 | (cp >> 12)));
      out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
      out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    } else {
      out.push_back(static_cast<char>(0xF0 | (cp >> 18)));
      out.push_back(static_cast<char>(0x80 | ((cp >> 12) & 0x3F)));
      out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
      out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    }
  }

  Expected<std::uint32_t> parse_hex4() {
    if (pos_ + 4 > text_.size()) {
      return fail("four hexadecimal digits after \\u");
    }
    std::uint32_t value = 0;
    for (int i = 0; i < 4; ++i) {
      char c = text_[pos_ + static_cast<std::size_t>(i)];
      std::uint32_t digit = 0;
      if (c >= '0' && c <= '9') {
        digit = static_cast<std::uint32_t>(c - '0');
      } else if (c >= 'a' && c <= 'f') {
        digit = static_cast<std::uint32_t>(c - 'a' + 10);
      } else if (c >= 'A' && c <= 'F') {
        digit = static_cast<std::uint32_t>(c - 'A' + 10);
      } else {
        return fail_at(pos_ + static_cast<std::size_t>(i),
                       "a hexadecimal digit");
      }
      value = (value << 4) | digit;
    }
    pos_ += 4;
    return value;
  }

  Expected<std::string> parse_string() {
    ++pos_;  // opening quote
    std::string out;
    for (;;) {
      if (eof())
        return fail("'\"' to close the string");
      char c = text_[pos_];
      if (c == '"') {
        ++pos_;
        return out;
      }
      if (c == '\\') {
        ++pos_;
        if (eof())
          return fail("an escape character after '\\'");
        char e = text_[pos_++];
        switch (e) {
          case '"':
            out.push_back('"');
            break;
          case '\\':
            out.push_back('\\');
            break;
          case '/':
            out.push_back('/');
            break;
          case 'n':
            out.push_back('\n');
            break;
          case 'r':
            out.push_back('\r');
            break;
          case 't':
            out.push_back('\t');
            break;
          case 'b':
            out.push_back('\b');
            break;
          case 'f':
            out.push_back('\f');
            break;
          case 'u': {
            std::uint32_t cp = MC_TRY(parse_hex4());
            // Combine a surrogate pair when one is actually present; a lone
            // surrogate is passed through as-is rather than rejected, since it
            // can only have come from our own writer or a hand edit.
            if (cp >= 0xD800 && cp <= 0xDBFF && pos_ + 1 < text_.size() &&
                text_[pos_] == '\\' && text_[pos_ + 1] == 'u') {
              std::size_t save = pos_;
              pos_ += 2;
              std::uint32_t low = MC_TRY(parse_hex4());
              if (low >= 0xDC00 && low <= 0xDFFF) {
                cp = 0x10000 + ((cp - 0xD800) << 10) + (low - 0xDC00);
              } else {
                pos_ = save;
              }
            }
            append_utf8(cp, out);
            break;
          }
          default:
            return fail_at(pos_ - 1,
                           "a valid escape (\\\" \\\\ \\/ \\b \\f "
                           "\\n \\r \\t \\uXXXX)");
        }
        continue;
      }
      if (static_cast<unsigned char>(c) < 0x20) {
        return fail("an escape sequence rather than a raw control character");
      }
      out.push_back(c);
      ++pos_;
    }
  }

  Expected<Json> parse_number() {
    std::size_t start = pos_;
    if (!eof() && peek() == '-')
      ++pos_;

    std::size_t int_start = pos_;
    while (!eof() && peek() >= '0' && peek() <= '9')
      ++pos_;
    if (pos_ == int_start)
      return fail_at(start, "a value");

    if (!eof() && peek() == '.') {
      ++pos_;
      std::size_t frac_start = pos_;
      while (!eof() && peek() >= '0' && peek() <= '9')
        ++pos_;
      if (pos_ == frac_start)
        return fail("a digit after the decimal point");
    }

    if (!eof() && (peek() == 'e' || peek() == 'E')) {
      ++pos_;
      if (!eof() && (peek() == '+' || peek() == '-'))
        ++pos_;
      std::size_t exp_start = pos_;
      while (!eof() && peek() >= '0' && peek() <= '9')
        ++pos_;
      if (pos_ == exp_start)
        return fail("a digit in the number's exponent");
    }

    // strtod needs a NUL-terminated buffer; the token is short by
    // construction, so a copy costs nothing worth optimising away.
    std::string token(text_.substr(start, pos_ - start));
    return Json(std::strtod(token.c_str(), nullptr));
  }

  std::string_view text_;
  Op op_;
  std::size_t pos_ = 0;
};

}  // namespace

Expected<Json> json_parse(std::string_view text, Op op) {
  Parser parser(text, op);
  return parser.parse_document();
}

}  // namespace mc
