#pragma once

#include <cstddef>
#include <cstdint>
#include <map>
#include <optional>
#include <span>
#include <vector>

namespace ketphone::media {

// Fixed-delay jitter buffer for 20 ms frames, keyed by extended RTP sequence number. It waits
// until `target_frames` frames are queued, then releases one frame per pop in sequence order.
// A missing frame is reported so the caller can conceal it; a frame that arrives after its slot
// is dropped. When the queue grows well past the target (the sender's clock runs fast or a
// burst arrived), the oldest frames are dropped to bring latency back down.
class JitterBuffer {
 public:
  explicit JitterBuffer(size_t target_frames);

  enum class PutResult { Stored, Late, Duplicate };
  PutResult put(int64_t sequence, std::span<const uint8_t> payload);

  enum class PopResult {
    // `frame` holds the next frame.
    Played,
    // The next frame is missing; play concealment.
    Missing,
    // Still filling up to the target; play silence without counting it as loss.
    Buffering,
  };
  PopResult pop(std::vector<uint8_t>& frame);

  size_t size() const { return frames_.size(); }
  size_t target_frames() const { return target_; }
  void reset();

 private:
  size_t target_;
  std::map<int64_t, std::vector<uint8_t>> frames_;
  std::optional<int64_t> next_;
  size_t missing_in_a_row_ = 0;
};

}  // namespace ketphone::media
