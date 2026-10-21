#include "sip/random.hpp"

#include <stdlib.h>
#include <unistd.h>

#include <algorithm>
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

bool secure_random(std::span<uint8_t> out) {
#if defined(__APPLE__)
  // The iOS SDKs declare no getentropy (macOS keeps it in <sys/random.h>); arc4random_buf is in
  // <stdlib.h> on every Apple platform, draws from the kernel's cryptographic generator and cannot
  // fail.
  if (!out.empty()) ::arc4random_buf(out.data(), out.size());
  return true;
#else
  // getentropy is available on glibc 2.25+ and Android API 28+; it never returns short and accepts
  // at most 256 bytes per call.
  while (!out.empty()) {
    const size_t chunk = std::min<size_t>(out.size(), 256);
    if (::getentropy(out.data(), chunk) != 0) return false;
    out = out.subspan(chunk);
  }
  return true;
#endif
}

}  // namespace ketphone::sip
