#include "media/media_session.hpp"

#include "media/g711.hpp"
#include "sip/sdp.hpp"

namespace ketphone::media {
namespace {

// Concealment repeats the last good frame at half the level each time, then falls silent.
constexpr size_t kConcealRepeats = 3;

}  // namespace

MediaSession::MediaSession(SpscRing<int16_t>& capture, SpscRing<int16_t>& playout, size_t jitter_frames)
    : capture_(capture), playout_(playout), jitter_(jitter_frames) {
  frame_.reserve(kFrameSamples);
}

void MediaSession::start(uint32_t ssrc, uint16_t first_sequence, uint32_t first_timestamp) {
  // Whatever the microphone produced before the call connected must not be sent.
  capture_.discard();
  jitter_.reset();
  receive_ = ReceiveStatistics{};
  stats_ = MediaStats{};
  have_remote_ssrc_ = false;
  last_played_.fill(0);
  concealed_in_a_row_ = 0;
  send_header_ = RtpHeader{};
  send_header_.payload_type = sip::kPayloadPcma;
  send_header_.ssrc = ssrc;
  send_header_.sequence = first_sequence;
  send_header_.timestamp = first_timestamp;
  send_header_.marker = true;  // first packet of a talkspurt
  active_ = true;
}

void MediaSession::stop() { active_ = false; }

size_t MediaSession::next_packet(std::span<uint8_t> out) {
  std::array<int16_t, kFrameSamples> samples{};
  capture_.pop(samples.data(), samples.size());
  std::array<uint8_t, kFrameSamples> encoded{};
  alaw_encode(samples.data(), samples.size(), encoded.data());
  const size_t size = write_rtp(out, send_header_, encoded);
  if (size == 0) return 0;
  send_header_.marker = false;
  ++send_header_.sequence;
  send_header_.timestamp += kFrameSamples;
  ++stats_.packets_sent;
  return size;
}

void MediaSession::on_packet(std::span<const uint8_t> datagram, uint32_t arrival) {
  const auto packet = parse_rtp(datagram);
  if (!packet || packet->header.payload_type != sip::kPayloadPcma) return;  // DTMF and comfort noise ignored
  if (!have_remote_ssrc_ || packet->header.ssrc != remote_ssrc_) {
    // A new source (Asterisk re-bridging, for instance) restarts sequence tracking.
    have_remote_ssrc_ = true;
    remote_ssrc_ = packet->header.ssrc;
    receive_ = ReceiveStatistics{};
    jitter_.reset();
  }
  const int64_t sequence = receive_.on_packet(packet->header.sequence, packet->header.timestamp, arrival);
  ++stats_.packets_received;
  if (jitter_.put(sequence, packet->payload) == JitterBuffer::PutResult::Late) ++stats_.packets_late;
}

void MediaSession::play_frame() {
  std::array<int16_t, kFrameSamples> samples{};
  switch (jitter_.pop(frame_)) {
    case JitterBuffer::PopResult::Played: {
      const size_t count = std::min(frame_.size(), samples.size());
      alaw_decode(frame_.data(), count, samples.data());
      last_played_ = samples;
      concealed_in_a_row_ = 0;
      break;
    }
    case JitterBuffer::PopResult::Missing:
      ++stats_.frames_concealed;
      if (concealed_in_a_row_ < kConcealRepeats) {
        for (auto& sample : last_played_) sample = static_cast<int16_t>(sample / 2);
        samples = last_played_;
      }
      ++concealed_in_a_row_;
      break;
    case JitterBuffer::PopResult::Buffering:
      break;
  }
  playout_.push(samples.data(), samples.size());
}

MediaStats MediaSession::stats() const {
  MediaStats stats = stats_;
  stats.packets_lost = receive_.lost();
  stats.jitter_ms = receive_.jitter() / 8.0;
  return stats;
}

}  // namespace ketphone::media
