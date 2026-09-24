// The jitter buffer against simulated networks: a sender emits one frame every 20 ms, each frame
// reaches the receiver after a delay chosen by the test (or never), and the receiver pops one
// frame every 20 ms. Everything runs on a virtual clock, so each scenario is exact and repeatable
// on any machine.
#include <algorithm>
#include <cstdint>
#include <functional>
#include <optional>
#include <vector>

#include "check.hpp"
#include "media/jitter_buffer.hpp"

using namespace ketphone::media;

namespace {

// Delay in milliseconds for frame n, or nullopt when the network drops it.
using Link = std::function<std::optional<double>(int64_t n)>;

struct Outcome {
  int64_t played = 0;
  int64_t missing = 0;
  int64_t late = 0;
  uint64_t expanded = 0;
  uint64_t dropped = 0;
  uint64_t skipped = 0;
  // Send-to-playout time of every played frame, in milliseconds, in playout order.
  std::vector<double> latency;
  // Ticks at which a frame was missing, to see when the stream recovered.
  std::vector<int64_t> missing_ticks;

  // Latency over the last `count` frames played.
  double max_latency_of_last(size_t count) const {
    return *std::max_element(latency.end() - static_cast<ptrdiff_t>(count), latency.end());
  }
  double min_latency_of_last(size_t count) const {
    return *std::min_element(latency.end() - static_cast<ptrdiff_t>(count), latency.end());
  }
};

struct Options {
  size_t frames = 1000;
  int64_t initial_delay_ms = 60;
  // The receiver's tick is offset from the sender's, as two unrelated clocks are.
  double phase_ms = 7;
  // The sender's 20 ms is this many receiver milliseconds: its clock runs fast below 20.
  double sender_frame_ms = 20;
};

Outcome simulate(const Link& link, const Options& options = {}) {
  struct Arrival {
    double at_ms;
    int64_t sequence;
  };
  const auto frames = static_cast<int64_t>(options.frames);
  std::vector<Arrival> arrivals;
  for (int64_t n = 0; n < frames; ++n) {
    if (const auto delay = link(n)) {
      arrivals.push_back({static_cast<double>(n) * options.sender_frame_ms + *delay, n});
    }
  }
  std::stable_sort(arrivals.begin(), arrivals.end(), [](const Arrival& a, const Arrival& b) { return a.at_ms < b.at_ms; });

  JitterBuffer buffer(options.initial_delay_ms * 1000);
  Outcome outcome;
  std::vector<uint8_t> frame;
  size_t next_arrival = 0;
  const auto us = [](double ms) { return static_cast<int64_t>(ms * 1000); };
  for (int64_t tick = 0;; ++tick) {
    const double now = options.phase_ms + static_cast<double>(tick) * 20;
    for (; next_arrival < arrivals.size() && arrivals[next_arrival].at_ms <= now; ++next_arrival) {
      const int64_t sequence = arrivals[next_arrival].sequence;
      // The payload carries the sequence so the test can see which frame played.
      const std::vector<uint8_t> payload = {static_cast<uint8_t>(sequence >> 8), static_cast<uint8_t>(sequence)};
      if (buffer.put(sequence, payload, us(arrivals[next_arrival].at_ms)) == JitterBuffer::PutResult::Late) {
        ++outcome.late;
      }
    }
    // Once everything has arrived, only drain; trailing Missing pops are not loss.
    if (next_arrival == arrivals.size() && buffer.size() == 0) break;
    switch (buffer.pop(frame, us(now))) {
      case JitterBuffer::PopResult::Played: {
        ++outcome.played;
        const int64_t sequence = int64_t{frame[0]} << 8 | frame[1];
        outcome.latency.push_back(now - static_cast<double>(sequence) * options.sender_frame_ms);
        break;
      }
      case JitterBuffer::PopResult::Missing:
        ++outcome.missing;
        outcome.missing_ticks.push_back(tick);
        break;
      case JitterBuffer::PopResult::Expanded:
      case JitterBuffer::PopResult::Buffering:
        break;
    }
  }
  outcome.expanded = buffer.expanded();
  outcome.dropped = buffer.dropped();
  outcome.skipped = buffer.skipped();
  return outcome;
}

// A small deterministic generator; std distributions differ between standard libraries.
class Random {
 public:
  explicit Random(uint64_t seed) : state_(seed) {}
  double uniform() {  // [0, 1)
    state_ ^= state_ << 13;
    state_ ^= state_ >> 7;
    state_ ^= state_ << 17;
    return static_cast<double>(state_ >> 11) / 9007199254740992.0;
  }

 private:
  uint64_t state_;
};

// Uniform jitter, with the first frames as fast as possible: the worst start for a buffer that
// sizes itself from them.
Outcome jitter_up_to(double max_ms, uint64_t seed) {
  Random random(seed);
  return simulate([&](int64_t n) -> std::optional<double> {
    if (n < 3) return 0.0;
    return max_ms * random.uniform();
  });
}

}  // namespace

// On a clean path the buffer settles at its 10 ms margin plus less than a frame and a half of
// rounding, instead of holding the initial 60 ms for the whole call.
TEST(network_constant_delay_settles_at_a_short_buffer) {
  const auto outcome = simulate([](int64_t) { return 70.0; });
  CHECK_EQ(outcome.played + static_cast<int64_t>(outcome.dropped), int64_t{1000});
  CHECK_EQ(outcome.missing, int64_t{0});
  CHECK_EQ(outcome.late, int64_t{0});
  CHECK(outcome.dropped <= 3);
  CHECK(outcome.min_latency_of_last(500) >= 70 + 10);
  CHECK(outcome.max_latency_of_last(500) <= 70 + 10 + 30);
}

// 45 ms of jitter beat a fixed 60 ms buffer, whose real headroom was two frames: about one frame
// in eight arrived late. The adaptive buffer only misses the 1% tail it deliberately gives up.
TEST(network_jitter_past_the_initial_headroom_is_absorbed) {
  const auto outcome = jitter_up_to(45, 1);
  CHECK(outcome.late <= 10);
  CHECK(outcome.max_latency_of_last(500) <= 45 + 10 + 30);
}

TEST(network_jitter_of_80_ms_is_absorbed_at_about_that_delay) {
  const auto outcome = jitter_up_to(80, 2);
  CHECK(outcome.late <= 20);
  CHECK(outcome.min_latency_of_last(500) >= 80);
  CHECK(outcome.max_latency_of_last(500) <= 80 + 10 + 30);
}

// A route change that adds 80 ms costs only the frames that were in the gap.
TEST(network_delay_step_up_costs_only_the_gap) {
  const auto outcome = simulate([](int64_t n) { return n < 200 ? 10.0 : 90.0; });
  CHECK(outcome.missing <= 5);
  CHECK(outcome.late <= 1);
  CHECK(outcome.missing_ticks.back() < 220);
  CHECK(outcome.min_latency_of_last(500) >= 90);
}

// When the path gets faster again the buffer gives the latency back.
TEST(network_delay_step_down_is_given_back) {
  const auto outcome = simulate([](int64_t n) { return n < 200 ? 90.0 : 10.0; });
  CHECK_EQ(outcome.late, int64_t{0});
  CHECK(outcome.max_latency_of_last(300) <= 10 + 10 + 30);
}

TEST(network_loss_is_concealed_or_skipped_one_for_one) {
  Random random(3);
  int64_t lost = 0;
  const auto outcome = simulate([&](int64_t n) -> std::optional<double> {
    if (n >= 3 && random.uniform() < 0.03) {
      ++lost;
      return std::nullopt;
    }
    return 40.0;
  });
  CHECK(lost > 10);
  CHECK_EQ(outcome.late, int64_t{0});
  CHECK_EQ(outcome.missing + static_cast<int64_t>(outcome.skipped), lost);
  CHECK_EQ(outcome.played, 1000 - lost - static_cast<int64_t>(outcome.dropped));
}

// netem-style reordering: a frame overtaken by the next one still plays in order.
TEST(network_reordering_inside_the_buffer_is_not_loss) {
  const auto outcome = simulate([](int64_t n) { return n % 10 == 5 ? 45.0 : 20.0; });
  CHECK_EQ(outcome.missing, int64_t{0});
  CHECK_EQ(outcome.late, int64_t{0});
}

// Sender and receiver clocks never agree exactly; crystals are typically within 100 ppm. A sender
// 0.1% fast piles frames up, a sender 0.1% slow drains the buffer; either way playout follows
// without loss or growing latency.
TEST(network_clock_drift_is_absorbed_both_ways) {
  for (const double sender_frame_ms : {19.98, 20.02}) {
    Options options;
    options.frames = 5000;
    options.sender_frame_ms = sender_frame_ms;
    const auto outcome = simulate([](int64_t) { return 30.0; }, options);
    CHECK_EQ(outcome.late, int64_t{0});
    CHECK_EQ(outcome.missing, int64_t{0});
    // Transit is measured against the sequence number, so drift shows up as spread: 0.1% over
    // the five second window is 5 ms more buffer.
    CHECK(outcome.max_latency_of_last(1000) <= 30 + 10 + 30 + 5);
    CHECK(outcome.expanded + outcome.dropped > 0);  // the drift really was corrected for
  }
}
