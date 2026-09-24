#include <cstring>
#include <stdexcept>

#include "check.hpp"

namespace ketphone::test {

std::vector<Case>& cases() {
  static std::vector<Case> all;
  return all;
}

namespace {
struct Failure : std::runtime_error {
  using std::runtime_error::runtime_error;
};
}  // namespace

void fail(const char* file, int line, const std::string& message) {
  throw Failure(std::string(file) + ":" + std::to_string(line) + ": " + message);
}

}  // namespace ketphone::test

// Usage: ketphone-tests [substring]  runs the cases whose name contains the substring.
int main(int argc, char** argv) {
  const char* filter = argc > 1 ? argv[1] : nullptr;
  int passed = 0;
  int failed = 0;
  for (const auto& test_case : ketphone::test::cases()) {
    if (filter != nullptr && std::strstr(test_case.name, filter) == nullptr) continue;
    try {
      test_case.body();
      ++passed;
    } catch (const std::exception& error) {
      ++failed;
      std::printf("FAIL %s\n  %s\n", test_case.name, error.what());
    }
  }
  std::printf("%d passed, %d failed\n", passed, failed);
  return failed == 0 && passed > 0 ? 0 : 1;
}
