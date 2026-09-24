#pragma once

// A deliberately tiny test harness: no third-party dependency to vet or license.

#include <cstdio>
#include <functional>
#include <sstream>
#include <string>
#include <vector>

namespace ketphone::test {

struct Case {
  const char* name;
  std::function<void()> body;
};

std::vector<Case>& cases();
void fail(const char* file, int line, const std::string& message);

struct Registrar {
  Registrar(const char* name, std::function<void()> body) { cases().push_back({name, std::move(body)}); }
};

template <typename A, typename B>
void check_equal(const A& actual, const B& expected, const char* actual_text, const char* expected_text,
                 const char* file, int line) {
  if (actual == expected) return;
  std::ostringstream message;
  message << actual_text << " == " << expected_text << "\n    actual:   " << actual << "\n    expected: " << expected;
  fail(file, line, message.str());
}

}  // namespace ketphone::test

#define KP_CONCAT_INNER(a, b) a##b
#define KP_CONCAT(a, b) KP_CONCAT_INNER(a, b)

#define TEST(name)                                                                              \
  static void name();                                                                           \
  static const ::ketphone::test::Registrar KP_CONCAT(registrar_, name)(#name, name);            \
  static void name()

#define CHECK(condition)                                                                        \
  do {                                                                                          \
    if (!(condition)) ::ketphone::test::fail(__FILE__, __LINE__, "CHECK(" #condition ")");      \
  } while (false)

#define CHECK_EQ(actual, expected) \
  ::ketphone::test::check_equal((actual), (expected), #actual, #expected, __FILE__, __LINE__)
