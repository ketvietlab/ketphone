#pragma once

#include <cstddef>
#include <cstdint>
#include <span>

namespace ketphone::media {

// The ringing tone a caller hears while the far end rings and no early media arrives: 425 Hz, one
// second on and four seconds off, the cadence of Vietnamese networks. It is generated here, at the
// 8 kHz the engine plays at, so every platform hears the same tone without shipping a sound file.
class RingbackTone {
 public:
  static constexpr double kFrequencyHz = 425.0;
  static constexpr size_t kOnSamples = 8000;      // 1 s
  static constexpr size_t kCycleSamples = 40000;  // 1 s on + 4 s off
  // Peak amplitude: well below full scale, like a network's tone, so it never clips on a speaker.
  static constexpr int16_t kAmplitude = 6000;

  // Starts the next fill at the beginning of a tone burst.
  void reset() { position_ = 0; }

  // Writes the next samples: the tone, then silence for the rest of the cycle.
  void fill(std::span<int16_t> out);

 private:
  size_t position_ = 0;
};

}  // namespace ketphone::media
