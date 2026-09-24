#pragma once

#include <cstddef>
#include <cstdint>
#include <map>
#include <optional>
#include <span>
#include <vector>

namespace ketphone::media {

// Adaptive jitter buffer for 20 ms frames, keyed by extended RTP sequence number.
//
// Every frame's transit (arrival time minus the time its sequence number says it was sent) goes
// into a five second window. The playout delay the buffer aims for is the fastest transit in the
// window plus the spread up to the 99th percentile plus a small margin, so a clean network gets
// a short buffer and a jittery one a longer buffer. Playout moves towards that target one frame
// at a time: it grows by repeating a frame (Expanded) and shrinks by skipping a slot whose frame
// never came, or, at most every 200 ms, by discarding a frame.
//
// When the buffer has run dry and a frame turns up after its slot (the path got slower), playout
// steps back to that frame instead of dropping it, so a delay step costs only the gap.
//
// Times are microseconds on any monotonic clock shared by put and pop.
class JitterBuffer {
 public:
  // `initial_delay_us` is the playout delay used until a second of transit has been measured.
  explicit JitterBuffer(int64_t initial_delay_us);

  enum class PutResult { Stored, Late, Duplicate };
  PutResult put(int64_t sequence, std::span<const uint8_t> payload, int64_t arrival_us);

  enum class PopResult {
    // `frame` holds the next frame.
    Played,
    // The next frame is missing; play concealment.
    Missing,
    // Playout is growing its delay by one frame; play concealment without consuming a frame.
    Expanded,
    // Not started yet; play silence without counting it as loss.
    Buffering,
  };
  PopResult pop(std::vector<uint8_t>& frame, int64_t now_us);

  // How long the fastest frames wait before playout, as the buffer currently aims for.
  int64_t target_delay_us() const;

  size_t size() const { return frames_.size(); }
  // Frames played twice to grow the delay.
  uint64_t expanded() const { return expanded_; }
  // Frames that arrived in time but were discarded to shrink the delay.
  uint64_t dropped() const { return dropped_; }
  // Empty slots passed over to shrink the delay; their frames had been lost.
  uint64_t skipped() const { return skipped_; }
  void reset();

 private:
  void record_transit(int64_t transit_us);
  // The playout offset (pop time minus the frame's send time) the buffer aims for.
  int64_t desired_offset_us() const;

  int64_t initial_delay_us_;
  std::map<int64_t, std::vector<uint8_t>> frames_;
  std::optional<int64_t> next_;
  std::optional<int64_t> last_played_;
  size_t missing_in_a_row_ = 0;
  size_t pops_since_drop_ = 0;

  std::vector<int64_t> window_;
  size_t window_count_ = 0;
  size_t window_next_ = 0;
  mutable std::vector<int64_t> scratch_;

  uint64_t expanded_ = 0;
  uint64_t dropped_ = 0;
  uint64_t skipped_ = 0;
};

}  // namespace ketphone::media
