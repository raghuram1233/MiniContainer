// SPDX-License-Identifier: MIT
//
// Unit tests for src/core/json.cpp. Run without root; no filesystem access.
//
// This suite exists because state.json is the only thing standing between a
// crashed runtime and a permanently leaked cgroup or veth. Three properties
// are load-bearing and every one of them has tests here:
//
//   * dump() is deterministic (std::map keys, so byte-identical output for
//     identical content) - otherwise every lifecycle write is an unreadable
//     diff and "what changed?" becomes unanswerable.
//   * an integral number never grows a ".0" tail - a pid written as "1234.0"
//     is not an integer to jq, and as_int callers would silently truncate a
//     value they should have been able to trust.
//   * a corrupt file fails loudly with a byte offset instead of parsing into
//     something plausible - a half-written record that "loads" is worse than
//     one that refuses to.
//
// The accessor tests are the fourth: they must never throw, because their
// callers are teardown paths that have to keep going.

#include <cmath>
#include <cstdint>
#include <limits>
#include <string>
#include <vector>

#include "minicontainer/errors.h"
#include "minicontainer/json.h"

#include <gtest/gtest.h>

namespace mc {
namespace {

// Parses or fails the test with the parser's own diagnostic, which names the
// byte offset - far more useful on a regression than "expected true".
Json ParseOk(const std::string& text) {
  Expected<Json> r = json_parse(text);
  if (!r) {
    ADD_FAILURE() << "expected parse to succeed, got: " << r.error().message();
    return Json();
  }
  return std::move(r).value();
}

Error ParseErr(const std::string& text) {
  Expected<Json> r = json_parse(text);
  if (r) {
    ADD_FAILURE() << "expected parse to fail, got: " << r->dump(0);
    return Error::invalid(Op::ReadState, "unreached");
  }
  return std::move(r).error();
}

// dump -> parse -> dump. Equal output means nothing was lost in either
// direction, which is the only round-trip property that actually matters.
void ExpectRoundTrips(const Json& value) {
  const std::string once = value.dump(0);
  EXPECT_EQ(ParseOk(once).dump(0), once);
  const std::string pretty = value.dump(2);
  EXPECT_EQ(ParseOk(pretty).dump(0), once);
}

// ---------------------------------------------------------------------------
// Round-tripping every type.
// ---------------------------------------------------------------------------
TEST(JsonRoundTripTest, Null) {
  Json j;
  EXPECT_EQ(j.type(), Json::Type::Null);
  EXPECT_TRUE(j.is_null());
  EXPECT_EQ(j.dump(0), "null");
  EXPECT_TRUE(ParseOk("null").is_null());
  ExpectRoundTrips(j);
}

TEST(JsonRoundTripTest, Bool) {
  EXPECT_EQ(Json(true).dump(0), "true");
  EXPECT_EQ(Json(false).dump(0), "false");
  EXPECT_TRUE(ParseOk("true").as_bool());
  EXPECT_FALSE(ParseOk("false").as_bool(true));
  EXPECT_EQ(ParseOk("true").type(), Json::Type::Bool);
  ExpectRoundTrips(Json(true));
  ExpectRoundTrips(Json(false));
}

TEST(JsonRoundTripTest, Number) {
  EXPECT_EQ(ParseOk("3.5").as_number(), 3.5);
  EXPECT_EQ(ParseOk("-3.5").as_number(), -3.5);
  EXPECT_EQ(ParseOk("1e3").as_number(), 1000.0);
  EXPECT_EQ(ParseOk("1E+3").as_number(), 1000.0);
  EXPECT_EQ(ParseOk("1e-3").as_number(), 0.001);
  // A fractional double must survive dump/parse bit-for-bit; dump_number tries
  // %.15g, %.16g, %.17g precisely so this holds without always being ugly.
  const double kPi = 3.14159265358979;
  EXPECT_EQ(ParseOk(Json(kPi).dump(0)).as_number(), kPi);
  ExpectRoundTrips(Json(0.5));
}

TEST(JsonRoundTripTest, String) {
  EXPECT_EQ(Json("hello").dump(0), "\"hello\"");
  EXPECT_EQ(ParseOk("\"hello\"").as_string(), "hello");
  EXPECT_EQ(ParseOk("\"\"").as_string(), "");
  EXPECT_EQ(ParseOk("\"\"").type(), Json::Type::String);
  ExpectRoundTrips(Json("hello"));
}

TEST(JsonRoundTripTest, StringWithEveryEscapeSurvives) {
  // Container args and env values are arbitrary bytes; a tab or a quote in one
  // of them must not corrupt the record that has to be read back at teardown.
  const std::string ugly =
      "q\" b\\ s/ nl\n tab\t cr\r bs\b ff\f ctl\x01\x1f utf\xc3\xa9";
  Json j(ugly);
  Json back = ParseOk(j.dump(0));
  EXPECT_EQ(back.as_string(), ugly);
  ExpectRoundTrips(j);
}

TEST(JsonRoundTripTest, Array) {
  JsonArray a;
  a.emplace_back(std::int64_t{1});
  a.emplace_back("two");
  a.emplace_back(true);
  a.emplace_back();  // null
  Json j(std::move(a));
  EXPECT_EQ(j.dump(0), "[1,\"two\",true,null]");
  Json back = ParseOk(j.dump(0));
  ASSERT_EQ(back.as_array().size(), 4u);
  EXPECT_EQ(back.as_array()[0].as_int(), 1);
  EXPECT_EQ(back.as_array()[1].as_string(), "two");
  EXPECT_TRUE(back.as_array()[2].as_bool());
  EXPECT_TRUE(back.as_array()[3].is_null());
  ExpectRoundTrips(j);
}

TEST(JsonRoundTripTest, Object) {
  JsonObject o;
  o["b"] = Json("two");
  o["a"] = Json(std::int64_t{1});
  Json j(std::move(o));
  EXPECT_EQ(j.dump(0), "{\"a\":1,\"b\":\"two\"}");
  Json back = ParseOk(j.dump(0));
  EXPECT_EQ(back.type(), Json::Type::Object);
  EXPECT_EQ(back["a"].as_int(), 1);
  EXPECT_EQ(back["b"].as_string(), "two");
  ExpectRoundTrips(j);
}

TEST(JsonRoundTripTest, NestedCombination) {
  // Shaped like a real state.json fragment: objects inside arrays inside
  // objects, with an optional-looking absent key and every scalar type.
  Json inner;
  inner.object()["host_port"] = Json(std::int64_t{8080});
  inner.object()["protocol"] = Json("tcp");

  Json ports;
  ports.array().push_back(inner);
  ports.array().emplace_back(std::int64_t{2});

  Json root;
  root.object()["network"] = ports;
  root.object()["enable_nat"] = Json(true);
  root.object()["container_ip"] = Json();
  root.object()["dns"] = Json(JsonArray{Json("1.1.1.1"), Json("8.8.8.8")});
  root.object()["empty_obj"] = Json(JsonObject{});
  root.object()["empty_arr"] = Json(JsonArray{});

  Json back = ParseOk(root.dump(2));
  EXPECT_EQ(back["network"].as_array()[0]["host_port"].as_int(), 8080);
  EXPECT_EQ(back["network"].as_array()[0]["protocol"].as_string(), "tcp");
  EXPECT_EQ(back["network"].as_array()[1].as_int(), 2);
  EXPECT_TRUE(back["enable_nat"].as_bool());
  EXPECT_TRUE(back["container_ip"].is_null());
  EXPECT_EQ(back["dns"].as_array().size(), 2u);
  EXPECT_EQ(back["empty_obj"].type(), Json::Type::Object);
  EXPECT_EQ(back["empty_arr"].type(), Json::Type::Array);
  ExpectRoundTrips(root);
}

TEST(JsonRoundTripTest, EmptyArrayAndEmptyObject) {
  // An explicitly empty list is meaningful in our schema (no DNS servers, no
  // published ports); it must not degrade into null or vanish.
  Json arr(JsonArray{});
  Json obj(JsonObject{});
  EXPECT_EQ(arr.dump(0), "[]");
  EXPECT_EQ(obj.dump(0), "{}");
  // Even pretty-printed, an empty container stays on one line - there is
  // nothing to indent, and "[\n]" would be noise in every state file.
  EXPECT_EQ(arr.dump(2), "[]");
  EXPECT_EQ(obj.dump(2), "{}");
  EXPECT_EQ(ParseOk("[]").type(), Json::Type::Array);
  EXPECT_TRUE(ParseOk("[]").as_array().empty());
  EXPECT_EQ(ParseOk("{}").type(), Json::Type::Object);
  EXPECT_TRUE(ParseOk("{}").as_object().empty());
  EXPECT_EQ(ParseOk("[ ]").dump(0), "[]");
  EXPECT_EQ(ParseOk("{ }").dump(0), "{}");
}

// ---------------------------------------------------------------------------
// dump(0) vs dump(2), and determinism.
// ---------------------------------------------------------------------------
TEST(JsonDumpTest, SingleLineVersusPretty) {
  Json j;
  j.object()["a"] = Json(std::int64_t{1});
  j.object()["b"] = Json(JsonArray{Json(std::int64_t{1}), Json("x")});

  EXPECT_EQ(j.dump(0), "{\"a\":1,\"b\":[1,\"x\"]}");
  EXPECT_EQ(j.dump(2),
            "{\n"
            "  \"a\": 1,\n"
            "  \"b\": [\n"
            "    1,\n"
            "    \"x\"\n"
            "  ]\n"
            "}");
}

TEST(JsonDumpTest, ObjectKeysComeOutSorted) {
  // JsonObject is a std::map, so insertion order cannot leak into the file.
  // This is what makes a state.json rewrite a minimal, reviewable diff.
  Json a;
  a.object()["zebra"] = Json(std::int64_t{1});
  a.object()["apple"] = Json(std::int64_t{2});
  a.object()["Mango"] = Json(std::int64_t{3});

  Json b;
  b.object()["Mango"] = Json(std::int64_t{3});
  b.object()["zebra"] = Json(std::int64_t{1});
  b.object()["apple"] = Json(std::int64_t{2});

  EXPECT_EQ(a.dump(0), "{\"Mango\":3,\"apple\":2,\"zebra\":1}");
  EXPECT_EQ(a.dump(0), b.dump(0));
  EXPECT_EQ(a.dump(2), b.dump(2));
}

TEST(JsonDumpTest, ArrayOrderIsPreserved) {
  // Sorting applies to object keys only: argv order is semantic.
  Json j(JsonArray{Json("c"), Json("a"), Json("b")});
  EXPECT_EQ(j.dump(0), "[\"c\",\"a\",\"b\"]");
}

// ---------------------------------------------------------------------------
// Integers never acquire a ".0" tail.
// ---------------------------------------------------------------------------
TEST(JsonNumberTest, IntegersNeverGainAFractionalTail) {
  // A pid, an exit code, a byte count, and a starttime all go through this.
  // "1234.0" would parse as a double elsewhere (jq -e, a future reader) and
  // would stop being an integer the moment anyone else touched the file.
  struct Case {
    std::int64_t value;
    const char* text;
  };
  const Case cases[] = {
      {0, "0"},
      {1, "1"},
      {-1, "-1"},
      {7, "7"},
      {1234, "1234"},
      {65535, "65535"},
      {2147483647, "2147483647"},
      {-2147483648LL, "-2147483648"},
      {4294967296LL, "4294967296"},              // 4 GiB as a memory limit
      {268435456LL, "268435456"},                // 256 MiB
      {1756500000000LL, "1756500000000"},        // millisecond timestamp
      {9007199254740991LL, "9007199254740991"},  // 2^53 - 1, exact in a double
  };
  for (const Case& c : cases) {
    Json j(c.value);
    EXPECT_EQ(j.dump(0), c.text) << "value: " << c.value;
    EXPECT_EQ(j.dump(0).find('.'), std::string::npos) << "value: " << c.value;
    EXPECT_EQ(j.dump(0).find('e'), std::string::npos) << "value: " << c.value;
    EXPECT_EQ(ParseOk(j.dump(0)).as_int(), c.value);
  }
}

TEST(JsonNumberTest, LargeUnsignedValuesStayIntegral) {
  const std::uint64_t large[] = {0u, 4294967295u, 68719476736u,
                                 9007199254740991u};
  for (std::uint64_t v : large) {
    Json j(v);
    const std::string text = j.dump(0);
    EXPECT_EQ(text.find('.'), std::string::npos) << "value: " << v;
    EXPECT_EQ(text.find('e'), std::string::npos) << "value: " << v;
    EXPECT_EQ(ParseOk(text).as_uint(), v);
  }
}

TEST(JsonNumberTest, DoubleWithAWholeValueAlsoLosesTheTail) {
  // Resources::cpus is a double; --cpus 2 must not persist as "2.0" and then
  // read back differently from --cpus 2 written by another code path.
  EXPECT_EQ(Json(2.0).dump(0), "2");
  EXPECT_EQ(Json(0.0).dump(0), "0");
  EXPECT_EQ(Json(-4.0).dump(0), "-4");
  // ...but a genuinely fractional one keeps its fraction.
  EXPECT_EQ(Json(0.5).dump(0), "0.5");
  EXPECT_EQ(Json(1.5).dump(0), "1.5");
}

TEST(JsonNumberTest, NonFiniteBecomesNullRatherThanUnparseableOutput) {
  // JSON has no spelling for NaN or infinity. Emitting "nan" would produce a
  // state file we could never read back, which is strictly worse than a null.
  EXPECT_EQ(Json(std::nan("")).dump(0), "null");
  EXPECT_EQ(Json(HUGE_VAL).dump(0), "null");
  EXPECT_EQ(Json(-HUGE_VAL).dump(0), "null");
}

// ---------------------------------------------------------------------------
// json_escape.
// ---------------------------------------------------------------------------
TEST(JsonEscapeTest, IncludesTheSurroundingQuotes) {
  EXPECT_EQ(json_escape(""), "\"\"");
  EXPECT_EQ(json_escape("plain"), "\"plain\"");
}

TEST(JsonEscapeTest, QuotesAndBackslashes) {
  EXPECT_EQ(json_escape("a\"b"), "\"a\\\"b\"");
  EXPECT_EQ(json_escape("a\\b"), "\"a\\\\b\"");
  // A Windows-looking bind-mount source is the realistic case for a run of
  // backslashes; each one has to double.
  EXPECT_EQ(json_escape("a\\\\b"), "\"a\\\\\\\\b\"");
}

TEST(JsonEscapeTest, NewlineTabCarriageReturnAndFriends) {
  EXPECT_EQ(json_escape("\n"), "\"\\n\"");
  EXPECT_EQ(json_escape("\t"), "\"\\t\"");
  EXPECT_EQ(json_escape("\r"), "\"\\r\"");
  EXPECT_EQ(json_escape("\b"), "\"\\b\"");
  EXPECT_EQ(json_escape("\f"), "\"\\f\"");
  EXPECT_EQ(json_escape("a\nb\tc"), "\"a\\nb\\tc\"");
}

TEST(JsonEscapeTest, ControlCharactersUseTheUnicodeForm) {
  // \u00XX is the only spelling that survives a round trip for a control
  // character with no short escape; a raw byte here would make the file
  // unparseable by us and by everyone else.
  EXPECT_EQ(json_escape(std::string("\x01", 1)), "\"\\u0001\"");
  EXPECT_EQ(json_escape(std::string("\x1f", 1)), "\"\\u001f\"");
  EXPECT_EQ(json_escape(std::string("\0", 1)), "\"\\u0000\"");
  EXPECT_EQ(json_escape(std::string("a\x0b"
                                    "b",
                                    3)),
            "\"a\\u000bb\"");
}

TEST(JsonEscapeTest, HighBytesPassThroughUnchanged) {
  // Our strings are UTF-8. Escaping them would only make state.json harder to
  // read for the human the pretty-printer exists for.
  EXPECT_EQ(json_escape("\xc3\xa9"), "\"\xc3\xa9\"");
}

TEST(JsonEscapeTest, EscapedFormsParseBackToTheOriginalBytes) {
  const std::string raw = std::string("\x01\x0b\x1f\"\\\n\t\r\b\f", 10);
  EXPECT_EQ(ParseOk(json_escape(raw)).as_string(), raw);
  // \/ is a legal (if pointless) escape on input even though we never emit it.
  EXPECT_EQ(ParseOk("\"a\\/b\"").as_string(), "a/b");
  // \uXXXX decodes to UTF-8 on the way in.
  EXPECT_EQ(ParseOk("\"\\u00e9\"").as_string(), "\xc3\xa9");
}

// ---------------------------------------------------------------------------
// Parse errors. Every one has to name a byte offset - that is the difference
// between "your state file is corrupt" and a diagnosable report.
// ---------------------------------------------------------------------------
TEST(JsonParseErrorTest, TruncatedObject) {
  Error e = ParseErr("{\"a\": 1");
  EXPECT_NE(e.message().find("byte offset 7"), std::string::npos)
      << e.message();
  EXPECT_EQ(e.op(), Op::ReadState);
}

TEST(JsonParseErrorTest, TruncatedArray) {
  Error e = ParseErr("[1, 2");
  EXPECT_NE(e.message().find("byte offset 5"), std::string::npos)
      << e.message();
}

TEST(JsonParseErrorTest, EmptyInput) {
  Error e = ParseErr("");
  EXPECT_NE(e.message().find("byte offset 0"), std::string::npos)
      << e.message();
}

TEST(JsonParseErrorTest, TruncatedLiteral) {
  Error e = ParseErr("tru");
  EXPECT_NE(e.message().find("byte offset"), std::string::npos) << e.message();
}

TEST(JsonParseErrorTest, TrailingGarbageAfterTheTopLevelValue) {
  // A state file with anything after the closing brace has been appended to,
  // not written by us. Accepting the prefix would hide that entirely.
  Error e = ParseErr("{\"a\":1} trailing");
  EXPECT_NE(e.message().find("byte offset 8"), std::string::npos)
      << e.message();
  EXPECT_NE(e.message().find("end of input"), std::string::npos) << e.message();

  Error e2 = ParseErr("1 2");
  EXPECT_NE(e2.message().find("byte offset 2"), std::string::npos)
      << e2.message();

  // Two concatenated documents - what a non-atomic rewrite could leave behind.
  ParseErr("{}{}");
}

TEST(JsonParseErrorTest, MalformedNumber) {
  Error e = ParseErr("{\"a\": 1.}");
  EXPECT_NE(e.message().find("byte offset 8"), std::string::npos)
      << e.message();
  EXPECT_NE(e.message().find("decimal point"), std::string::npos)
      << e.message();

  Error e2 = ParseErr("[1e]");
  EXPECT_NE(e2.message().find("exponent"), std::string::npos) << e2.message();

  // A lone '-' is not a number; it must not silently become 0.
  Error e3 = ParseErr("-");
  EXPECT_NE(e3.message().find("byte offset"), std::string::npos)
      << e3.message();
}

TEST(JsonParseErrorTest, UnterminatedString) {
  Error e = ParseErr("{\"a\": \"oops}");
  EXPECT_NE(e.message().find("byte offset 12"), std::string::npos)
      << e.message();
  EXPECT_NE(e.message().find("close the string"), std::string::npos)
      << e.message();

  // A truncated key is the same failure one field earlier.
  ParseErr("{\"a");
  // A trailing backslash leaves the escape itself incomplete.
  ParseErr("\"a\\");
}

TEST(JsonParseErrorTest, RawControlCharacterInsideAString) {
  // Rejecting this is what forces \u00XX on output to be correct: if we
  // accepted raw control bytes we would never notice a writer that emitted
  // them.
  Error e = ParseErr(std::string("\"a\nb\"", 5));
  EXPECT_NE(e.message().find("byte offset 2"), std::string::npos)
      << e.message();
}

TEST(JsonParseErrorTest, InvalidEscapeAndShortUnicode) {
  Error e = ParseErr("\"a\\qb\"");
  EXPECT_NE(e.message().find("byte offset 3"), std::string::npos)
      << e.message();
  ParseErr("\"\\u12\"");
  ParseErr("\"\\uZZZZ\"");
}

TEST(JsonParseErrorTest, StructuralErrors) {
  ParseErr("{1: 2}");       // key is not a string
  ParseErr("{\"a\" 1}");    // missing ':'
  ParseErr("{\"a\": 1,}");  // trailing comma
  ParseErr("[1,]");         // trailing comma
  ParseErr("[1 2]");        // missing ','
}

TEST(JsonParseErrorTest, DepthIsBoundedRatherThanOverflowingTheStack) {
  // A hand-edited or garbage state file must not be able to crash the process
  // that is trying to diagnose it.
  const std::string deep(500, '[');
  Error e = ParseErr(deep);
  EXPECT_NE(e.message().find("depth limit"), std::string::npos) << e.message();
}

TEST(JsonParseErrorTest, WhitespaceAroundAValueIsFine) {
  EXPECT_EQ(ParseOk(" \t\r\n {\"a\" : 1} \n ").dump(0), "{\"a\":1}");
}

// ---------------------------------------------------------------------------
// Accessors: fallback on mismatch, never a throw.
// ---------------------------------------------------------------------------
TEST(JsonAccessorTest, WrongTypeReturnsTheFallback) {
  // A state file written by an older version can have any field missing or of
  // the wrong shape. Degrading to a default keeps a teardown running; throwing
  // would strand the cgroup and veth this record is the only pointer to.
  const Json s("text");
  const Json n(std::int64_t{42});
  const Json b(true);
  const Json null;

  EXPECT_FALSE(s.as_bool());
  EXPECT_TRUE(s.as_bool(true));
  EXPECT_EQ(s.as_number(1.5), 1.5);
  EXPECT_EQ(s.as_int(-7), -7);
  EXPECT_EQ(s.as_uint(9u), 9u);

  EXPECT_EQ(n.as_string(), "");
  EXPECT_TRUE(n.as_array().empty());
  EXPECT_TRUE(n.as_object().empty());
  EXPECT_TRUE(n.as_bool(true));

  EXPECT_EQ(b.as_int(3), 3);
  EXPECT_EQ(b.as_string(), "");

  EXPECT_EQ(null.as_int(5), 5);
  EXPECT_EQ(null.as_string(), "");
  EXPECT_FALSE(null.as_bool());
  EXPECT_TRUE(null.as_array().empty());
  EXPECT_TRUE(null.as_object().empty());
}

TEST(JsonAccessorTest, NegativeNumberIsNotAnUnsigned) {
  // Casting -1 to uint64 would yield 18446744073709551615; as a memory limit
  // that is not merely wrong, it is the kernel enforcing an absurd value.
  const Json neg(std::int64_t{-1});
  EXPECT_EQ(neg.as_int(), -1);
  EXPECT_EQ(neg.as_uint(42u), 42u);
  EXPECT_EQ(ParseOk("-5").as_uint(0u), 0u);
}

TEST(JsonAccessorTest, IntegerAccessorTruncatesTowardZero) {
  EXPECT_EQ(ParseOk("2.9").as_int(), 2);
  EXPECT_EQ(ParseOk("-2.9").as_int(), -2);
}

TEST(JsonAccessorTest, MissingKeyReturnsANullJsonSoChainsAreSafe) {
  Json j;
  j.object()["a"] = Json(JsonObject{});

  EXPECT_TRUE(j["nope"].is_null());
  EXPECT_FALSE(j.contains("nope"));
  EXPECT_TRUE(j.contains("a"));
  // The chain the header promises: a partial file must not be able to throw
  // on the read path.
  EXPECT_EQ(j["a"]["b"].as_string(), "");
  EXPECT_EQ(j["nope"]["deeper"]["deeper_still"].as_string(), "");
  EXPECT_EQ(j["nope"]["deeper"].as_int(11), 11);
}

TEST(JsonAccessorTest, SubscriptOnANonObjectIsNullNotAnError) {
  const Json arr(JsonArray{Json(std::int64_t{1})});
  const Json str("x");
  EXPECT_TRUE(arr["anything"].is_null());
  EXPECT_TRUE(str["anything"].is_null());
  EXPECT_FALSE(arr.contains("anything"));
  EXPECT_FALSE(str.contains("anything"));
}

TEST(JsonAccessorTest, BuildersRetypeADefaultConstructedValue) {
  Json j;
  j.object()["k"] = Json(std::int64_t{1});
  EXPECT_EQ(j.type(), Json::Type::Object);

  // Switching kind clears the old contents rather than leaving a hybrid.
  j.array().emplace_back(std::int64_t{2});
  EXPECT_EQ(j.type(), Json::Type::Array);
  EXPECT_EQ(j.dump(0), "[2]");
  EXPECT_TRUE(j.as_object().empty());
}

TEST(JsonParseTest, DuplicateKeyKeepsTheLastValue) {
  // Documented policy: our writer never emits a duplicate, and rejecting one
  // would turn a harmless hand edit into an unloadable state file.
  EXPECT_EQ(ParseOk("{\"a\":1,\"a\":2}")["a"].as_int(), 2);
}

TEST(JsonParseTest, OpIsCarriedIntoTheError) {
  // The caller's Op is what makes the message say "Failed to write container
  // state" rather than a generic parse complaint.
  Expected<Json> r = json_parse("{", Op::WriteState);
  ASSERT_FALSE(r.has_value());
  EXPECT_EQ(r.error().op(), Op::WriteState);
}

// ---------------------------------------------------------------------------
// Regression: casting an out-of-range double to an integer is undefined
// behaviour, not a wrap.
//
// as_int() used to cast unconditionally, so a corrupt state file holding
// "pid": 1e300 produced 0 on at least one toolchain - and pid 0 means "my
// whole process group" to kill(2), so the UB sat one step away from
// signalling the wrong processes. These accessors promise to degrade to their
// fallback rather than misbehave; that promise has to cover this.
// ---------------------------------------------------------------------------
TEST(JsonRangeTest, OutOfRangeDoublesFallBackInsteadOfCasting) {
  EXPECT_EQ(Json(1e300).as_int(-7), -7);
  EXPECT_EQ(Json(-1e300).as_int(-7), -7);
  EXPECT_EQ(Json(1e300).as_uint(9), 9U);
}

TEST(JsonRangeTest, InRangeValuesStillConvert) {
  // The guard must not reject ordinary values - a range check that rejects
  // everything would "fix" the UB by breaking the accessor.
  EXPECT_EQ(Json(0).as_int(-1), 0);
  EXPECT_EQ(Json(-42).as_int(0), -42);
  EXPECT_EQ(Json(4294967296.0).as_uint(0), 4294967296ULL);
  EXPECT_EQ(Json(9007199254740991.0).as_int(0), 9007199254740991LL);
}

TEST(JsonRangeTest, NotANumberFallsBack) {
  // NaN fails every comparison, which is why the range guards are written as
  // negated tests rather than as `num_ > limit`.
  const double nan = std::numeric_limits<double>::quiet_NaN();
  EXPECT_EQ(Json(nan).as_int(5), 5);
  EXPECT_EQ(Json(nan).as_uint(5), 5U);
}

}  // namespace
}  // namespace mc
