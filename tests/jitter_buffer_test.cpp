#include <vector>

#include "check.hpp"
#include "media/jitter_buffer.hpp"

using namespace ketphone::media;
using Pop = JitterBuffer::PopResult;
using Put = JitterBuffer::PutResult;

namespace {

std::vector<uint8_t> frame_of(uint8_t value) { return std::vector<uint8_t>(160, value); }

// The time frame `sequence` was sent, plus `ms`, in microseconds.
int64_t at(int64_t sequence, int64_t ms) { return sequence * 20'000 + ms * 1000; }

}  // namespace

TEST(jitter_buffer_waits_for_the_initial_delay_then_plays_in_order) {
  JitterBuffer buffer(60'000);
  std::vector<uint8_t> out;
  CHECK(buffer.put(101, frame_of(1), at(101, 0)) == Put::Stored);
  CHECK(buffer.put(100, frame_of(0), at(100, 5)) == Put::Stored);
  CHECK(buffer.pop(out, at(100, 40)) == Pop::Buffering);
  CHECK(buffer.put(101, frame_of(1), at(101, 1)) == Put::Duplicate);
  CHECK(buffer.pop(out, at(100, 60)) == Pop::Played);
  CHECK_EQ(int{out[0]}, 0);
  CHECK(buffer.pop(out, at(101, 60)) == Pop::Played);
  CHECK_EQ(int{out[0]}, 1);
  CHECK_EQ(buffer.target_delay_us(), int64_t{60'000});
}

TEST(jitter_buffer_reports_gaps_and_drops_late_frames_while_others_wait) {
  JitterBuffer buffer(20'000);
  std::vector<uint8_t> out;
  buffer.put(10, frame_of(10), at(10, 0));
  buffer.put(12, frame_of(12), at(12, 0));
  CHECK(buffer.pop(out, at(10, 20)) == Pop::Played);
  CHECK(buffer.pop(out, at(11, 20)) == Pop::Missing);  // 11 never came in time
  // Frame 12 is queued, so stepping back for 11 would only delay 12.
  CHECK(buffer.put(11, frame_of(11), at(11, 25)) == Put::Late);
  // Its 25 ms transit still counts: the target grows to 35 ms, so playout first stretches...
  CHECK_EQ(buffer.target_delay_us(), int64_t{35'000});
  CHECK(buffer.pop(out, at(12, 20)) == Pop::Expanded);
  // ...and then plays frame 12 a frame later.
  CHECK(buffer.pop(out, at(12, 40)) == Pop::Played);
  CHECK_EQ(int{out[0]}, 12);
}

// The path got slower: nothing is queued when the late frame arrives, so playout steps back and
// plays it rather than concealing every frame until the stream is restarted.
TEST(jitter_buffer_steps_back_for_a_late_frame_when_it_ran_dry) {
  JitterBuffer buffer(20'000);
  std::vector<uint8_t> out;
  buffer.put(1, frame_of(1), at(1, 0));
  CHECK(buffer.pop(out, at(1, 20)) == Pop::Played);
  CHECK(buffer.pop(out, at(2, 20)) == Pop::Missing);
  CHECK(buffer.pop(out, at(3, 20)) == Pop::Missing);
  CHECK(buffer.put(2, frame_of(2), at(2, 50)) == Put::Stored);
  // The 50 ms transit raised the target to 60 ms; playout now runs 60 ms behind the sender.
  CHECK_EQ(buffer.target_delay_us(), int64_t{60'000});
  CHECK(buffer.pop(out, at(2, 60)) == Pop::Played);
  CHECK_EQ(int{out[0]}, 2);
  CHECK(buffer.put(3, frame_of(3), at(3, 50)) == Put::Stored);
  CHECK(buffer.pop(out, at(3, 60)) == Pop::Played);
  CHECK_EQ(int{out[0]}, 3);
}

// Stepping back past a frame that already played would replay the stream out of order.
TEST(jitter_buffer_never_steps_back_behind_a_played_frame) {
  JitterBuffer buffer(20'000);
  std::vector<uint8_t> out;
  buffer.put(1, frame_of(1), at(1, 0));
  buffer.put(3, frame_of(3), at(3, 0));
  CHECK(buffer.pop(out, at(1, 20)) == Pop::Played);
  CHECK(buffer.pop(out, at(2, 20)) == Pop::Missing);
  CHECK(buffer.pop(out, at(3, 20)) == Pop::Played);
  CHECK(buffer.put(2, frame_of(2), at(2, 70)) == Put::Late);
}

TEST(jitter_buffer_starts_over_after_the_stream_stops) {
  JitterBuffer buffer(20'000);
  std::vector<uint8_t> out;
  buffer.put(1, frame_of(1), at(1, 0));
  CHECK(buffer.pop(out, at(1, 20)) == Pop::Played);
  for (int64_t n = 2; n < 12; ++n) CHECK(buffer.pop(out, at(n, 20)) == Pop::Missing);
  CHECK(buffer.pop(out, at(12, 20)) == Pop::Buffering);
  // After the pause the stream resumes at the initial delay rather than as late frames.
  CHECK(buffer.put(50, frame_of(50), at(50, 0)) == Put::Stored);
  CHECK(buffer.pop(out, at(50, 10)) == Pop::Buffering);
  CHECK(buffer.pop(out, at(50, 20)) == Pop::Played);
}

// Shrinking skips empty slots first, since that costs no audio at all.
TEST(jitter_buffer_shrinks_through_lost_frames_for_free) {
  JitterBuffer buffer(100'000);
  std::vector<uint8_t> out;
  // A second of 0 ms transit ends the warm-up and lowers the target to the 10 ms margin.
  // Frames 1 and 2 were lost.
  for (int64_t n = 0; n < 60; ++n) {
    if (n != 1 && n != 2) buffer.put(n, frame_of(static_cast<uint8_t>(n)), at(n, 0));
  }
  CHECK_EQ(buffer.target_delay_us(), int64_t{10'000});
  // Playout starts 90 ms above the target, but dropping audio right away is not allowed.
  CHECK(buffer.pop(out, at(0, 100)) == Pop::Played);
  CHECK_EQ(int{out[0]}, 0);
  // Passing over the two lost slots is free, so the next pop plays frame 3.
  CHECK(buffer.pop(out, at(1, 100)) == Pop::Played);
  CHECK_EQ(int{out[0]}, 3);
  CHECK_EQ(buffer.skipped(), uint64_t{2});
  CHECK_EQ(buffer.dropped(), uint64_t{0});
}

// Without an empty slot to pass over, one frame of real audio goes every 200 ms at most.
TEST(jitter_buffer_drops_audio_to_shrink_at_a_limited_rate) {
  JitterBuffer buffer(100'000);
  std::vector<uint8_t> out;
  for (int64_t n = 0; n < 60; ++n) buffer.put(n, frame_of(static_cast<uint8_t>(n)), at(n, 0));
  std::vector<int> played;
  for (int64_t tick = 0; tick < 25; ++tick) {
    CHECK(buffer.pop(out, at(tick, 100)) == Pop::Played);
    played.push_back(out[0]);
  }
  // 100 ms of playout against a 10 ms target: two drops, 200 ms apart, bring it within a frame
  // and a half of the target, and there it stays.
  CHECK_EQ(buffer.dropped(), uint64_t{2});
  CHECK_EQ(played[9], 9);
  CHECK_EQ(played[10], 11);
  CHECK_EQ(played[19], 20);
  CHECK_EQ(played[20], 22);
  CHECK_EQ(played[24], 26);
}
