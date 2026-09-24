#include "media/g711.hpp"

namespace ketphone::media {
namespace {

// Upper bound of each of the eight segments, on the 13-bit magnitude.
constexpr int kSegmentEnd[8] = {0x1f, 0x3f, 0x7f, 0xff, 0x1ff, 0x3ff, 0x7ff, 0xfff};

}  // namespace

uint8_t alaw_encode(int16_t sample) {
  int magnitude = sample >> 3;
  int mask;
  if (magnitude >= 0) {
    mask = 0xd5;  // sign bit set, then even bits inverted
  } else {
    mask = 0x55;
    magnitude = -magnitude - 1;
  }
  int segment = 0;
  while (segment < 8 && magnitude > kSegmentEnd[segment]) ++segment;
  if (segment >= 8) return static_cast<uint8_t>(0x7f ^ mask);
  int code = segment << 4;
  code |= segment < 2 ? (magnitude >> 1) & 0x0f : (magnitude >> segment) & 0x0f;
  return static_cast<uint8_t>(code ^ mask);
}

int16_t alaw_decode(uint8_t code) {
  const int value = code ^ 0x55;
  int magnitude = (value & 0x0f) << 4;
  const int segment = (value & 0x70) >> 4;
  if (segment == 0) {
    magnitude += 8;
  } else {
    magnitude = (magnitude + 0x108) << (segment - 1);
  }
  return static_cast<int16_t>((value & 0x80) ? magnitude : -magnitude);
}

void alaw_encode(const int16_t* samples, size_t count, uint8_t* out) {
  for (size_t i = 0; i < count; ++i) out[i] = alaw_encode(samples[i]);
}

void alaw_decode(const uint8_t* codes, size_t count, int16_t* out) {
  for (size_t i = 0; i < count; ++i) out[i] = alaw_decode(codes[i]);
}

}  // namespace ketphone::media
