#include <cmath>
#include <cstdint>
#include <numbers>
#include <vector>

#include "check.hpp"
#include "media/ringback.hpp"

using ketphone::media::RingbackTone;

namespace {

std::vector<int16_t> take(RingbackTone& tone, size_t count) {
  std::vector<int16_t> out(count);
  tone.fill(out);
  return out;
}

double power(const std::vector<int16_t>& samples, size_t from, size_t to) {
  double total = 0;
  for (size_t i = from; i < to; ++i) total += static_cast<double>(samples[i]) * samples[i];
  return total / static_cast<double>(to - from);
}

}  // namespace

TEST(ringback_is_one_second_of_tone_then_four_of_silence) {
  RingbackTone tone;
  const auto cycle = take(tone, RingbackTone::kCycleSamples);
  CHECK(power(cycle, 1000, 7000) > 1e6);
  CHECK_EQ(power(cycle, 8000, 40000), 0.0);
  // The next cycle starts the burst again.
  const auto next = take(tone, 8000);
  CHECK(power(next, 1000, 7000) > 1e6);
}

TEST(ringback_is_a_425_hz_tone_below_full_scale) {
  RingbackTone tone;
  const auto burst = take(tone, 8000);
  int peak = 0;
  for (const int16_t sample : burst) peak = std::max(peak, std::abs(static_cast<int>(sample)));
  CHECK(peak <= RingbackTone::kAmplitude);
  CHECK(peak > RingbackTone::kAmplitude * 9 / 10);
  // Goertzel at 425 Hz holds nearly all the energy of the burst's steady part.
  const double w = 2 * std::numbers::pi * 425.0 / 8000;
  const double coefficient = 2 * std::cos(w);
  double s1 = 0;
  double s2 = 0;
  double total = 0;
  for (size_t i = 800; i < 7200; ++i) {
    const double s0 = burst[i] + coefficient * s1 - s2;
    s2 = s1;
    s1 = s0;
    total += static_cast<double>(burst[i]) * burst[i];
  }
  const double energy = s1 * s1 + s2 * s2 - coefficient * s1 * s2;
  CHECK(2 * energy / (6400.0 * total) > 0.95);
}

TEST(ringback_burst_fades_in_and_out_without_a_step) {
  RingbackTone tone;
  const auto burst = take(tone, 8100);
  CHECK(std::abs(burst[0]) < 100);
  CHECK(std::abs(burst[7999]) < 400);
  CHECK_EQ(int{burst[8050]}, 0);
}

TEST(ringback_fills_in_pieces_like_in_one_go_and_restarts_on_reset) {
  RingbackTone whole;
  const auto expected = take(whole, 3000);
  RingbackTone pieces;
  std::vector<int16_t> got;
  for (int i = 0; i < 3000 / 160 + 1; ++i) {
    const auto part = take(pieces, 160);
    got.insert(got.end(), part.begin(), part.end());
  }
  for (size_t i = 0; i < expected.size(); ++i) CHECK_EQ(int{got[i]}, int{expected[i]});
  pieces.reset();
  const auto again = take(pieces, 3000);
  for (size_t i = 0; i < expected.size(); ++i) CHECK_EQ(int{again[i]}, int{expected[i]});
}
