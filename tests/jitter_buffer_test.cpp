#include <vector>

#include "check.hpp"
#include "media/jitter_buffer.hpp"

using namespace ketphone::media;
using Pop = JitterBuffer::PopResult;

namespace {
std::vector<uint8_t> frame_of(uint8_t value) { return std::vector<uint8_t>(160, value); }
}  // namespace

TEST(jitter_buffer_waits_for_the_target_then_plays_in_order) {
  JitterBuffer buffer(3);
  std::vector<uint8_t> out;
  CHECK(buffer.put(101, frame_of(1)) == JitterBuffer::PutResult::Stored);
  CHECK(buffer.put(100, frame_of(0)) == JitterBuffer::PutResult::Stored);
  CHECK(buffer.pop(out) == Pop::Buffering);
  CHECK(buffer.put(102, frame_of(2)) == JitterBuffer::PutResult::Stored);
  CHECK(buffer.put(102, frame_of(2)) == JitterBuffer::PutResult::Duplicate);
  for (uint8_t expected = 0; expected < 3; ++expected) {
    CHECK(buffer.pop(out) == Pop::Played);
    CHECK_EQ(int{out[0]}, int{expected});
  }
}

TEST(jitter_buffer_reports_gaps_and_drops_late_frames) {
  JitterBuffer buffer(2);
  std::vector<uint8_t> out;
  buffer.put(10, frame_of(10));
  buffer.put(12, frame_of(12));
  CHECK(buffer.pop(out) == Pop::Played);   // 10
  CHECK(buffer.pop(out) == Pop::Missing);  // 11 never came in time
  CHECK(buffer.put(11, frame_of(11)) == JitterBuffer::PutResult::Late);
  CHECK(buffer.pop(out) == Pop::Played);  // 12
  CHECK_EQ(int{out[0]}, 12);
}

TEST(jitter_buffer_rebuffers_after_the_stream_stops) {
  JitterBuffer buffer(2);
  std::vector<uint8_t> out;
  buffer.put(1, frame_of(1));
  buffer.put(2, frame_of(2));
  buffer.pop(out);
  buffer.pop(out);
  for (int i = 0; i < 10; ++i) CHECK(buffer.pop(out) == Pop::Missing);
  CHECK(buffer.pop(out) == Pop::Buffering);
  // After the pause the stream resumes at the target delay rather than as late frames.
  CHECK(buffer.put(50, frame_of(50)) == JitterBuffer::PutResult::Stored);
}

TEST(jitter_buffer_sheds_latency_when_frames_pile_up) {
  JitterBuffer buffer(2);
  std::vector<uint8_t> out;
  for (int64_t sequence = 0; sequence < 20; ++sequence) buffer.put(sequence, frame_of(static_cast<uint8_t>(sequence)));
  CHECK(buffer.pop(out) == Pop::Played);
  // Only target * 2 + 2 = 6 frames are kept, so playback jumps to the newest of them.
  CHECK_EQ(int{out[0]}, 14);
  CHECK_EQ(buffer.size(), size_t{5});
}
