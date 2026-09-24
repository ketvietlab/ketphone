#include "media/jitter_buffer.hpp"

#include <algorithm>

namespace ketphone::media {
namespace {

// After this many consecutive missing frames with nothing queued, the stream has stopped (or
// paused); go back to buffering so it restarts at the target delay.
constexpr size_t kMissingBeforeRebuffer = 10;

// A frame this far ahead of the playout point means the stream jumped; start over from it.
constexpr int64_t kMaxAhead = 500;

}  // namespace

JitterBuffer::JitterBuffer(size_t target_frames) : target_(std::max<size_t>(1, target_frames)) {}

JitterBuffer::PutResult JitterBuffer::put(int64_t sequence, std::span<const uint8_t> payload) {
  if (next_) {
    if (sequence < *next_) return PutResult::Late;
    if (sequence - *next_ > kMaxAhead) reset();
  }
  const auto [it, inserted] = frames_.try_emplace(sequence, payload.begin(), payload.end());
  return inserted ? PutResult::Stored : PutResult::Duplicate;
}

JitterBuffer::PopResult JitterBuffer::pop(std::vector<uint8_t>& frame) {
  if (!next_) {
    if (frames_.size() < target_) return PopResult::Buffering;
    next_ = frames_.begin()->first;
  }

  // Keep at most twice the target (plus slack) queued; beyond that latency only grows.
  const size_t ceiling = target_ * 2 + 2;
  while (frames_.size() > ceiling) {
    frames_.erase(frames_.begin());
    next_ = frames_.begin()->first;
  }

  const auto it = frames_.find(*next_);
  ++*next_;
  if (it != frames_.end()) {
    frame = std::move(it->second);
    frames_.erase(it);
    missing_in_a_row_ = 0;
    return PopResult::Played;
  }

  ++missing_in_a_row_;
  if (frames_.empty() && missing_in_a_row_ >= kMissingBeforeRebuffer) reset();
  return PopResult::Missing;
}

void JitterBuffer::reset() {
  frames_.clear();
  next_.reset();
  missing_in_a_row_ = 0;
}

}  // namespace ketphone::media
