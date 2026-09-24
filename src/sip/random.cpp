#include "sip/random.hpp"

#include <mutex>
#include <random>

namespace ketphone::sip {
namespace {

std::mutex generator_mutex;

std::mt19937& generator() {
  static std::mt19937 instance{std::random_device{}()};
  return instance;
}

}  // namespace

uint32_t random_u32() {
  std::lock_guard lock(generator_mutex);
  return static_cast<uint32_t>(generator()());
}

std::string random_hex(size_t bytes) {
  static constexpr char kHex[] = "0123456789abcdef";
  std::string out;
  out.reserve(bytes * 2);
  std::lock_guard lock(generator_mutex);
  for (size_t i = 0; i < bytes; ++i) {
    const auto byte = static_cast<uint8_t>(generator()());
    out.push_back(kHex[byte >> 4]);
    out.push_back(kHex[byte & 0x0f]);
  }
  return out;
}

}  // namespace ketphone::sip
