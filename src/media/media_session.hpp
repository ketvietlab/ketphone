#pragma once

#include <array>
#include <cstdint>
#include <span>
#include <vector>

#include "media/jitter_buffer.hpp"
#include "media/rtp.hpp"
#include "media/spsc_ring.hpp"

namespace ketphone::media {

inline constexpr size_t kFrameSamples = 160;  // 20 ms at 8 kHz
inline constexpr size_t kMaxPacketSize = kRtpHeaderSize + kFrameSamples;

struct MediaStats {
  uint64_t packets_sent = 0;
  uint64_t packets_received = 0;
  uint64_t packets_lost = 0;
  uint64_t packets_late = 0;
  uint64_t frames_concealed = 0;
  double jitter_ms = 0;
};

// The media half of one call, without sockets or clocks: the engine calls next_packet and
// play_frame every 20 ms and on_packet for each datagram that arrives on the RTP socket.
// Samples come from `capture` (microphone) and go to `playout` (speaker); both rings are shared
// with the realtime audio thread.
class MediaSession {
 public:
  MediaSession(SpscRing<int16_t>& capture, SpscRing<int16_t>& playout, size_t jitter_frames);

  void start(uint32_t ssrc, uint16_t first_sequence, uint32_t first_timestamp);
  void stop();
  bool active() const { return active_; }

  // Encodes the next 20 ms of captured audio (silence when the microphone fell behind) into an
  // RTP packet. Returns the packet size.
  size_t next_packet(std::span<uint8_t> out);

  // arrival is in RTP timestamp units (1/8000 s) from any fixed origin.
  void on_packet(std::span<const uint8_t> datagram, uint32_t arrival);

  // Moves the next 20 ms from the jitter buffer to the playout ring, concealing a lost frame.
  void play_frame();

  MediaStats stats() const;

 private:
  SpscRing<int16_t>& capture_;
  SpscRing<int16_t>& playout_;
  JitterBuffer jitter_;
  ReceiveStatistics receive_;
  bool active_ = false;
  bool have_remote_ssrc_ = false;
  uint32_t remote_ssrc_ = 0;
  RtpHeader send_header_;
  MediaStats stats_;
  std::vector<uint8_t> frame_;
  std::array<int16_t, kFrameSamples> last_played_{};
  size_t concealed_in_a_row_ = 0;
};

}  // namespace ketphone::media
