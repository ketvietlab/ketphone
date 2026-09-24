// The jitter buffer against simulated networks: a sender emits one frame every 20 ms, each frame
// reaches the receiver after a delay chosen by the test (or never), and the receiver pops one
// frame every 20 ms. Everything runs on a virtual clock, so each scenario is exact and repeatable
// on any machine. These are the baselines an adaptive jitter buffer has to beat.
#include <algorithm>
#include <cstdint>
#include <functional>
#include <optional>
#include <vector>

#include "check.hpp"
#include "media/jitter_buffer.hpp"

using namespace ketphone::media;

namespace {

constexpr int64_t kFrameMs = 20;

// Delay in milliseconds for frame n, or nullopt when the network drops it.
using Link = std::function<std::optional<double>(int64_t n)>;

struct Outcome {
  int64_t played = 0;
  int64_t missing = 0;
  int64_t late = 0;
  // Send-to-playout time of every played frame, in milliseconds.
  std::vector<double> latency;
  // Ticks at which a frame was missing, to see when the stream recovered.
  std::vector<int64_t> missing_ticks;

  double min_latency() const { return *std::min_element(latency.begin(), latency.end()); }
  double max_latency() const { return *std::max_element(latency.begin(), latency.end()); }
};

// The receiver's tick is offset from the sender's by `phase_ms`, as two unrelated clocks are.
Outcome simulate(const Link& link, int64_t frames, size_t target_frames, double phase_ms = 7) {
  struct Arrival {
    double at;
    int64_t sequence;
  };
  std::vector<Arrival> arrivals;
  for (int64_t n = 0; n < frames; ++n) {
    if (const auto delay = link(n)) arrivals.push_back({static_cast<double>(n * kFrameMs) + *delay, n});
  }
  std::stable_sort(arrivals.begin(), arrivals.end(), [](const Arrival& a, const Arrival& b) { return a.at < b.at; });

  JitterBuffer buffer(target_frames);
  Outcome outcome;
  std::vector<uint8_t> frame;
  size_t next_arrival = 0;
  // Keep ticking long enough to drain whatever the slowest frame left queued.
  const int64_t ticks = frames + 50;
  for (int64_t tick = 0; tick < ticks; ++tick) {
    const double now = phase_ms + static_cast<double>(tick * kFrameMs);
    for (; next_arrival < arrivals.size() && arrivals[next_arrival].at <= now; ++next_arrival) {
      const int64_t sequence = arrivals[next_arrival].sequence;
      // The payload carries the sequence so the test can see which frame played.
      const std::vector<uint8_t> payload = {static_cast<uint8_t>(sequence >> 8), static_cast<uint8_t>(sequence)};
      if (buffer.put(sequence, payload) == JitterBuffer::PutResult::Late) ++outcome.late;
    }
    if (tick >= frames) {
      // Past the end of the stream only drain; trailing Missing pops are not loss.
      if (buffer.size() == 0) break;
    }
    switch (buffer.pop(frame)) {
      case JitterBuffer::PopResult::Played: {
        ++outcome.played;
        const int64_t sequence = int64_t{frame[0]} << 8 | frame[1];
        outcome.latency.push_back(now - static_cast<double>(sequence * kFrameMs));
        break;
      }
      case JitterBuffer::PopResult::Missing:
        if (tick < frames) {
          ++outcome.missing;
          outcome.missing_ticks.push_back(tick);
        }
        break;
      case JitterBuffer::PopResult::Buffering:
        break;
    }
  }
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

}  // namespace

TEST(network_constant_delay_plays_everything_at_a_fixed_latency) {
  const auto outcome = simulate([](int64_t) { return 70.0; }, 500, 3);
  CHECK_EQ(outcome.played, int64_t{500});
  CHECK_EQ(outcome.missing, int64_t{0});
  CHECK_EQ(outcome.late, int64_t{0});
  CHECK(outcome.max_latency() - outcome.min_latency() < 0.001);
  // 70 ms on the wire plus two frames waiting for the third, plus the tick offset.
  CHECK(outcome.min_latency() >= 70 + 2 * kFrameMs);
  CHECK(outcome.min_latency() < 70 + 3 * kFrameMs);
}

// The buffer starts once it holds three frames, so its headroom is counted from how fast those
// first frames arrived: two frames plus the wait for the next tick, not three frames. With the
// first frames at zero delay and the tick 1 ms after them, frame n plays at 41 + 20n ms.
Outcome jitter_up_to(double max_ms, uint64_t seed) {
  Random random(seed);
  return simulate(
      [&](int64_t n) -> std::optional<double> {
        if (n < 3) return 0.0;  // the worst start: the first frames came in fastest
        return max_ms * random.uniform();
      },
      1000, 3, /*phase_ms=*/1);
}

TEST(network_jitter_inside_the_headroom_costs_nothing) {
  const auto outcome = jitter_up_to(40, 1);
  CHECK_EQ(outcome.missing, int64_t{0});
  CHECK_EQ(outcome.late, int64_t{0});
}

// Jitter just past the headroom turns into late frames although nothing was lost; the nominal
// 60 ms buffer does not cover 45 ms of jitter.
TEST(network_jitter_beyond_the_headroom_becomes_late_frames) {
  const auto outcome = jitter_up_to(45, 1);
  CHECK(outcome.late > 0);
  CHECK_EQ(outcome.played + outcome.late, int64_t{1000});
}

// A step in delay larger than the headroom (a route change, Wi-Fi to 4G) makes every frame late
// until the buffer gives up after ten missing frames and starts over at the new delay.
TEST(network_delay_step_costs_a_rebuffer_then_recovers) {
  const auto outcome = simulate([](int64_t n) { return n < 200 ? 10.0 : 90.0; }, 1000, 3);
  CHECK(outcome.missing >= 10);
  CHECK(outcome.missing_ticks.back() < 250);  // recovered well before the end
  // After recovery playout sits at the new delay.
  CHECK(outcome.latency.back() >= 90);
}

TEST(network_loss_is_concealed_one_for_one_at_constant_delay) {
  Random random(3);
  int64_t dropped = 0;
  const auto outcome = simulate(
      [&](int64_t n) -> std::optional<double> {
        // Keep the first frames so the start is not what is under test.
        if (n >= 3 && random.uniform() < 0.03) {
          ++dropped;
          return std::nullopt;
        }
        return 40.0;
      },
      1000, 3);
  CHECK(dropped > 10);
  CHECK_EQ(outcome.missing, dropped);
  CHECK_EQ(outcome.late, int64_t{0});
  CHECK_EQ(outcome.played, 1000 - dropped);
}

// netem-style reordering: a frame overtaken by the next one (35 ms against 0 ms, sent 20 ms
// apart) still plays in order, because it is inside the 41 ms headroom.
TEST(network_reordering_inside_the_buffer_is_not_loss) {
  const auto outcome = simulate([](int64_t n) { return n % 10 == 5 ? 35.0 : 0.0; }, 500, 3, /*phase_ms=*/1);
  CHECK_EQ(outcome.played, int64_t{500});
  CHECK_EQ(outcome.missing, int64_t{0});
  CHECK_EQ(outcome.late, int64_t{0});
}
