#include "media/jitter_buffer.hpp"

#include <algorithm>

namespace ketphone::media {
namespace {

constexpr int64_t kFrameUs = 20'000;

// Transit samples kept: five seconds of 20 ms frames.
constexpr size_t kWindow = 250;

// Until this many samples (one second) exist, the configured initial delay is a floor.
constexpr size_t kWarmup = 50;

// Headroom above the 99th percentile spread, for scheduling noise on either end.
constexpr int64_t kMarginUs = 10'000;

constexpr int64_t kMaxDelayUs = 300'000;

// Shrink only once playout is this far past a frame above the target, so that growing by one
// frame never immediately triggers a shrink.
constexpr int64_t kShrinkAboveUs = kFrameUs + 10'000;

// Discarding real audio is audible; do it at most once per this many pops (200 ms).
constexpr size_t kPopsBetweenDrops = 10;

// How far back playout may step for a late frame when the buffer ran dry.
constexpr int64_t kMaxRewind = 15;

// After this many consecutive missing frames with nothing queued, the stream has stopped (or
// paused); start over so it resumes at a fresh delay.
constexpr size_t kMissingBeforeRebuffer = 10;

// A frame this far ahead of the playout point means the stream jumped; start over from it.
constexpr int64_t kMaxAhead = 500;

}  // namespace

JitterBuffer::JitterBuffer(int64_t initial_delay_us)
    : initial_delay_us_(std::clamp<int64_t>(initial_delay_us, kMarginUs, kMaxDelayUs)), window_(kWindow) {
  scratch_.reserve(kWindow);
}

JitterBuffer::PutResult JitterBuffer::put(int64_t sequence, std::span<const uint8_t> payload, int64_t arrival_us) {
  if (next_ && sequence - *next_ > kMaxAhead) reset();
  // Late frames count too: they are the evidence that the delay is too short.
  record_transit(arrival_us - sequence * kFrameUs);

  if (next_ && sequence < *next_) {
    const bool dry = frames_.empty();
    const bool unplayed_since = !last_played_ || sequence > *last_played_;
    if (!dry || !unplayed_since || *next_ - sequence > kMaxRewind) return PutResult::Late;
    next_ = sequence;
    missing_in_a_row_ = 0;
  }
  const auto [it, inserted] = frames_.try_emplace(sequence, payload.begin(), payload.end());
  return inserted ? PutResult::Stored : PutResult::Duplicate;
}

JitterBuffer::PopResult JitterBuffer::pop(std::vector<uint8_t>& frame, int64_t now_us) {
  if (!next_) {
    if (frames_.empty()) return PopResult::Buffering;
    const int64_t first = frames_.begin()->first;
    if (now_us - first * kFrameUs < desired_offset_us()) return PopResult::Buffering;
    next_ = first;
  }

  const int64_t desired = desired_offset_us();
  int64_t offset = now_us - *next_ * kFrameUs;
  if (offset < desired) {
    ++expanded_;
    ++pops_since_drop_;
    return PopResult::Expanded;
  }

  while (offset > desired + kShrinkAboveUs && !frames_.empty()) {
    const auto it = frames_.find(*next_);
    if (it == frames_.end()) {
      ++skipped_;
    } else if (pops_since_drop_ >= kPopsBetweenDrops) {
      frames_.erase(it);
      ++dropped_;
      pops_since_drop_ = 0;
    } else {
      break;
    }
    ++*next_;
    offset -= kFrameUs;
  }
  ++pops_since_drop_;

  const auto it = frames_.find(*next_);
  if (it != frames_.end()) {
    last_played_ = *next_;
    ++*next_;
    frame = std::move(it->second);
    frames_.erase(it);
    missing_in_a_row_ = 0;
    return PopResult::Played;
  }

  ++*next_;
  ++missing_in_a_row_;
  if (frames_.empty() && missing_in_a_row_ >= kMissingBeforeRebuffer) reset();
  return PopResult::Missing;
}

int64_t JitterBuffer::target_delay_us() const {
  if (window_count_ == 0) return initial_delay_us_;
  const int64_t fastest = *std::min_element(window_.begin(), window_.begin() + static_cast<ptrdiff_t>(window_count_));
  return desired_offset_us() - fastest;
}

void JitterBuffer::reset() {
  frames_.clear();
  next_.reset();
  last_played_.reset();
  missing_in_a_row_ = 0;
  pops_since_drop_ = 0;
  window_count_ = 0;
  window_next_ = 0;
}

void JitterBuffer::record_transit(int64_t transit_us) {
  window_[window_next_] = transit_us;
  window_next_ = (window_next_ + 1) % kWindow;
  window_count_ = std::min(window_count_ + 1, kWindow);
}

int64_t JitterBuffer::desired_offset_us() const {
  // Only called once a frame has been put, so the window is not empty.
  scratch_.assign(window_.begin(), window_.begin() + static_cast<ptrdiff_t>(window_count_));
  const auto fastest = *std::min_element(scratch_.begin(), scratch_.end());
  // Rounded up, so that a handful of samples does not pick the fastest one.
  const auto percentile = scratch_.begin() + static_cast<ptrdiff_t>(((window_count_ - 1) * 99 + 99) / 100);
  std::nth_element(scratch_.begin(), percentile, scratch_.end());
  int64_t delay = *percentile - fastest + kMarginUs;
  if (window_count_ < kWarmup) delay = std::max(delay, initial_delay_us_);
  return fastest + std::clamp<int64_t>(delay, kMarginUs, kMaxDelayUs);
}

}  // namespace ketphone::media
