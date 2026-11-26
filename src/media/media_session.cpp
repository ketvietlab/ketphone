#include "media/media_session.hpp"

#include <algorithm>

#include "media/g711.hpp"
#include "sip/sdp.hpp"

namespace ketphone::media {
namespace {

// Concealment repeats the last good frame at half the level each time, then falls silent.
constexpr size_t kConcealRepeats = 3;

}  // namespace

std::optional<uint8_t> dtmf_event_code(char key) {
  if (key >= '0' && key <= '9') return static_cast<uint8_t>(key - '0');
  if (key == '*') return 10;
  if (key == '#') return 11;
  if (key >= 'A' && key <= 'D') return static_cast<uint8_t>(12 + key - 'A');
  if (key >= 'a' && key <= 'd') return static_cast<uint8_t>(12 + key - 'a');
  return std::nullopt;
}

MediaSession::MediaSession(SpscRing<int16_t>& capture, SpscRing<int16_t>& playout, int64_t initial_delay_us)
    : capture_(capture), playout_(playout), jitter_(initial_delay_us) {
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
  sending_ = true;
  receiving_ = true;
  telephone_event_.reset();
  tones_.clear();
  tone_.reset();
  gap_frames_ = 0;
  active_ = true;
}

void MediaSession::stop() {
  active_ = false;
  tones_.clear();
  tone_.reset();
}

void MediaSession::set_telephone_event(std::optional<uint8_t> payload_type) {
  if (payload_type == telephone_event_) return;
  telephone_event_ = payload_type;
  // A key half sent under the old type would end under another; the far end hears it cut short.
  tones_.clear();
  if (tone_) {
    tone_.reset();
    send_header_.marker = true;
  }
}

void MediaSession::set_direction(bool send, bool receive) {
  if (send && !sending_) send_header_.marker = true;  // a new talkspurt after the hold
  if (!send) {
    tones_.clear();
    tone_.reset();
    gap_frames_ = 0;
  }
  if (receive != receiving_) {
    // What was buffered before the hold must not play after it, and the far end may come back
    // with another source.
    jitter_.reset();
    receive_ = ReceiveStatistics{};
    have_remote_ssrc_ = false;
  }
  sending_ = send;
  receiving_ = receive;
}

bool MediaSession::queue_dtmf(std::string_view keys, uint32_t duration_ms) {
  if (!active_ || !sending_ || !telephone_event_ || keys.empty()) return false;
  std::vector<Tone> tones;
  tones.reserve(keys.size());
  const uint32_t ms = duration_ms == 0 ? kDtmfDefaultMs : std::clamp(duration_ms, kDtmfMinimumMs, kDtmfMaximumMs);
  // Whole packets: the last one carries the full duration.
  const uint32_t frames = (ms * 8 + kFrameSamples - 1) / kFrameSamples;
  for (const char key : keys) {
    const auto event = dtmf_event_code(key);
    if (!event) return false;
    tones.push_back({*event, static_cast<uint32_t>(frames * kFrameSamples)});
  }
  tones_.insert(tones_.end(), tones.begin(), tones.end());
  return true;
}

size_t MediaSession::next_tone_packet(std::span<uint8_t> out) {
  PlayingTone& playing = *tone_;
  const bool first = playing.elapsed == 0;
  if (playing.end_packets == 0) playing.elapsed = std::min(playing.elapsed + uint32_t{kFrameSamples}, playing.tone.duration);
  const bool end = playing.elapsed >= playing.tone.duration;
  // RFC 4733 section 2.3: event, E bit and volume, then the duration so far.
  const std::array<uint8_t, 4> payload{
      playing.tone.event, static_cast<uint8_t>((end ? 0x80 : 0x00) | kDtmfVolume),
      static_cast<uint8_t>(playing.elapsed >> 8), static_cast<uint8_t>(playing.elapsed & 0xff)};
  RtpHeader header = send_header_;
  header.payload_type = *telephone_event_;
  header.marker = first;
  header.timestamp = playing.timestamp;  // every packet of an event carries the time it began
  const size_t size = write_rtp(out, header, payload);
  if (size == 0) return 0;
  ++send_header_.sequence;
  send_header_.timestamp += kFrameSamples;
  ++stats_.packets_sent;
  if (end && ++playing.end_packets >= kDtmfEndPackets) {
    tone_.reset();
    gap_frames_ = kDtmfGapFrames;
    send_header_.marker = true;  // audio after an event starts a talkspurt
  }
  return size;
}

size_t MediaSession::next_packet(std::span<uint8_t> out) {
  std::array<int16_t, kFrameSamples> samples{};
  capture_.pop(samples.data(), samples.size());
  if (!sending_) {
    // The clock goes on while nothing is sent, so the far end sees the hold as a pause.
    send_header_.timestamp += kFrameSamples;
    return 0;
  }
  if (!tone_ && gap_frames_ == 0 && !tones_.empty()) {
    tone_ = PlayingTone{tones_.front(), send_header_.timestamp, 0, 0};
    tones_.pop_front();
  }
  // The key replaces the microphone while it is held (RFC 4733 section 2.6).
  if (tone_) return next_tone_packet(out);
  if (gap_frames_ > 0) --gap_frames_;
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

void MediaSession::on_packet(std::span<const uint8_t> datagram, int64_t arrival_us) {
  if (!receiving_) return;  // on hold: nothing the far end sends is played
  const auto packet = parse_rtp(datagram);
  // Only A-law is audio. Telephone events, comfort noise and anything else are never decoded as
  // A-law, whatever payload type the far end gave them.
  if (!packet || packet->header.payload_type != sip::kPayloadPcma) return;
  if (!have_remote_ssrc_ || packet->header.ssrc != remote_ssrc_) {
    // A new source (Asterisk re-bridging, for instance) restarts sequence tracking.
    have_remote_ssrc_ = true;
    remote_ssrc_ = packet->header.ssrc;
    receive_ = ReceiveStatistics{};
    jitter_.reset();
  }
  // RFC 3550 jitter is computed in RTP timestamp units (1/8000 s); wrapping is harmless there.
  const auto arrival_rtp = static_cast<uint32_t>(arrival_us * 8 / 1000);
  const int64_t sequence = receive_.on_packet(packet->header.sequence, packet->header.timestamp, arrival_rtp);
  ++stats_.packets_received;
  if (jitter_.put(sequence, packet->payload, arrival_us) == JitterBuffer::PutResult::Late) ++stats_.packets_late;
}

void MediaSession::play_frame(int64_t now_us) {
  std::array<int16_t, kFrameSamples> samples{};
  const auto result = jitter_.pop(frame_, now_us);
  switch (result) {
    case JitterBuffer::PopResult::Played: {
      const size_t count = std::min(frame_.size(), samples.size());
      alaw_decode(frame_.data(), count, samples.data());
      last_played_ = samples;
      concealed_in_a_row_ = 0;
      break;
    }
    case JitterBuffer::PopResult::Missing:
    case JitterBuffer::PopResult::Expanded:
      if (result == JitterBuffer::PopResult::Missing) ++stats_.frames_concealed;
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
  stats.frames_expanded = jitter_.expanded();
  stats.frames_dropped = jitter_.dropped();
  stats.playout_delay_ms = static_cast<double>(jitter_.target_delay_us()) / 1000.0;
  return stats;
}

}  // namespace ketphone::media
