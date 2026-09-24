#include <cstdlib>

#include "check.hpp"
#include "media/g711.hpp"

using namespace ketphone::media;

TEST(alaw_known_codes) {
  CHECK_EQ(int{alaw_encode(0)}, 0xd5);
  CHECK_EQ(int{alaw_encode(-1)}, 0x55);
  CHECK_EQ(int{alaw_encode(32767)}, 0xaa);
  CHECK_EQ(int{alaw_encode(-32768)}, 0x2a);
  CHECK_EQ(int{alaw_decode(0xd5)}, 8);
  CHECK_EQ(int{alaw_decode(0x55)}, -8);
  CHECK_EQ(int{alaw_decode(0xaa)}, 32256);
  CHECK_EQ(int{alaw_decode(0x2a)}, -32256);
}

// Every code decodes to a value that encodes back to the same code.
TEST(alaw_decode_then_encode_is_identity) {
  for (int code = 0; code < 256; ++code) {
    CHECK_EQ(int{alaw_encode(alaw_decode(static_cast<uint8_t>(code)))}, code);
  }
}

// Quantisation error stays within half a step of the segment (about 3% of the magnitude).
TEST(alaw_error_is_bounded_and_monotonic) {
  int previous = alaw_decode(alaw_encode(-32768));
  for (int sample = -32768; sample <= 32767; sample += 7) {
    const int decoded = alaw_decode(alaw_encode(static_cast<int16_t>(sample)));
    CHECK(std::abs(decoded - sample) <= std::max(16, std::abs(sample) / 30));
    CHECK(decoded >= previous);
    previous = decoded;
  }
}
