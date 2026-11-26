#pragma once

#include <array>
#include <cstdint>
#include <deque>
#include <optional>
#include <span>
#include <string_view>
#include <vector>

#include "media/jitter_buffer.hpp"
#include "media/rtp.hpp"
#include "media/spsc_ring.hpp"

namespace ketphone::media {

inline constexpr size_t kFrameSamples = 160;  // 20 ms at 8 kHz
inline constexpr size_t kMaxPacketSize = kRtpHeaderSize + kFrameSamples;

// RFC 4733 events this side sends: how long a key is held by default and at most, how often the
// final packet goes out, and the audio between two keys.
inline constexpr uint32_t kDtmfDefaultMs = 160;
inline constexpr uint32_t kDtmfMinimumMs = 40;
inline constexpr uint32_t kDtmfMaximumMs = 5000;
inline constexpr size_t kDtmfEndPackets = 3;
inline constexpr size_t kDtmfGapFrames = 3;
// Power level of the events, as -dBm0 (RFC 4733 section 2.3.4).
inline constexpr uint8_t kDtmfVolume = 10;

// The RFC 4733 event code of a key: 0-9, * (10), # (11), A-D (12-15). Nothing for anything else.
std::optional<uint8_t> dtmf_event_code(char key);

struct MediaStats {
  uint64_t packets_sent = 0;
  uint64_t packets_received = 0;
  uint64_t packets_lost = 0;
  uint64_t packets_late = 0;
  uint64_t frames_concealed = 0;
  uint64_t frames_expanded = 0;
  uint64_t frames_dropped = 0;
  double jitter_ms = 0;
  double playout_delay_ms = 0;
};

// The media half of one call, without sockets or clocks: the engine calls next_packet and
// play_frame every 20 ms and on_packet for each datagram that arrives on the RTP socket. Times are
// microseconds on one monotonic clock.
// Samples come from `capture` (microphone) and go to `playout` (speaker); both rings are shared
// with the realtime audio thread.
class MediaSession {
 public:
  MediaSession(SpscRing<int16_t>& capture, SpscRing<int16_t>& playout, int64_t initial_delay_us);

  void start(uint32_t ssrc, uint16_t first_sequence, uint32_t first_timestamp);
  void stop();
  bool active() const { return active_; }

  // Payload type the far end takes RFC 4733 events on, as its SDP maps telephone-event/8000;
  // nothing when it does not. Keys queued for the old type are dropped when it changes.
  void set_telephone_event(std::optional<uint8_t> payload_type);
  std::optional<uint8_t> telephone_event() const { return telephone_event_; }

  // Whether this side sends media and plays what arrives, as the call's hold state says. Not
  // sending drops the keys still queued; the microphone keeps being drained either way.
  void set_direction(bool send, bool receive);
  bool sending() const { return sending_; }
  bool receiving() const { return receiving_; }

  // Queues keys ("0"-"9", "*", "#", "A"-"D") to send as RFC 4733 events, each held for
  // `duration_ms` (0 means kDtmfDefaultMs; clamped to kDtmfMinimumMs..kDtmfMaximumMs). Returns false and queues nothing
  // when a key is not one of those, no telephone-event type was negotiated, or media is not sent.
  bool queue_dtmf(std::string_view keys, uint32_t duration_ms);
  bool dtmf_pending() const { return tone_.has_value() || !tones_.empty(); }

  // Encodes the next 20 ms of captured audio (silence when the microphone fell behind) into an
  // RTP packet, or the next packet of a queued key in its place. Returns the packet size, 0 when
  // nothing is sent.
  size_t next_packet(std::span<uint8_t> out);

  void on_packet(std::span<const uint8_t> datagram, int64_t arrival_us);

  // Moves the next 20 ms from the jitter buffer to the playout ring, concealing a lost frame.
  // `now_us` is the frame's scheduled time.
  void play_frame(int64_t now_us);

  MediaStats stats() const;

 private:
  SpscRing<int16_t>& capture_;
  SpscRing<int16_t>& playout_;
  JitterBuffer jitter_;
  ReceiveStatistics receive_;
  struct Tone {
    uint8_t event = 0;
    uint32_t duration = 0;  // in RTP timestamp units
  };
  struct PlayingTone {
    Tone tone;
    uint32_t timestamp = 0;
    uint32_t elapsed = 0;
    size_t end_packets = 0;
  };

  size_t next_tone_packet(std::span<uint8_t> out);

  bool active_ = false;
  bool sending_ = true;
  bool receiving_ = true;
  std::optional<uint8_t> telephone_event_;
  std::deque<Tone> tones_;
  std::optional<PlayingTone> tone_;
  size_t gap_frames_ = 0;
  bool have_remote_ssrc_ = false;
  uint32_t remote_ssrc_ = 0;
  RtpHeader send_header_;
  MediaStats stats_;
  std::vector<uint8_t> frame_;
  std::array<int16_t, kFrameSamples> last_played_{};
  size_t concealed_in_a_row_ = 0;
};

}  // namespace ketphone::media
