#include "media/ringback.hpp"

#include <cmath>
#include <numbers>

namespace ketphone::media {
namespace {

// A burst fades in and out over 10 ms so that its edges do not click.
constexpr size_t kRampSamples = 80;

}  // namespace

void RingbackTone::fill(std::span<int16_t> out) {
  for (int16_t& sample : out) {
    if (position_ < kOnSamples) {
      double gain = 1.0;
      if (position_ < kRampSamples) gain = static_cast<double>(position_) / kRampSamples;
      const size_t left = kOnSamples - position_;
      if (left <= kRampSamples) gain = static_cast<double>(left) / kRampSamples;
      const double phase = 2.0 * std::numbers::pi * kFrequencyHz * static_cast<double>(position_) / 8000.0;
      sample = static_cast<int16_t>(std::lround(kAmplitude * gain * std::sin(phase)));
    } else {
      sample = 0;
    }
    position_ = (position_ + 1) % kCycleSamples;
  }
}

}  // namespace ketphone::media
