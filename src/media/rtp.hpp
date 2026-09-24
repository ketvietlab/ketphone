#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>

namespace ketphone::media {

inline constexpr size_t kRtpHeaderSize = 12;

struct RtpHeader {
  uint8_t payload_type = 0;
  bool marker = false;
  uint16_t sequence = 0;
  uint32_t timestamp = 0;
  uint32_t ssrc = 0;
};

struct RtpPacket {
  RtpHeader header;
  std::span<const uint8_t> payload;
};

// Writes a version 2 header without CSRCs or extension, then the payload. Returns the packet
// size, or 0 when it does not fit.
size_t write_rtp(std::span<uint8_t> out, const RtpHeader& header, std::span<const uint8_t> payload);

// Parses RTP, skipping CSRCs and header extensions and removing padding. Rejects RTCP (payload
// types 72-76 with the marker bit, per RFC 5761) and anything that is not version 2.
std::optional<RtpPacket> parse_rtp(std::span<const uint8_t> datagram);

// Receiver statistics of one stream, per RFC 3550 appendix A.1 (sequence tracking) and A.8
// (interarrival jitter).
class ReceiveStatistics {
 public:
  // Records a packet and returns its extended sequence number (sequence plus wrap cycles), which
  // keeps growing across the 16-bit wrap. arrival is in RTP timestamp units (1/8000 s).
  int64_t on_packet(uint16_t sequence, uint32_t timestamp, uint32_t arrival);

  uint64_t received() const { return received_; }
  // Packets expected from the sequence range minus packets received, never negative.
  uint64_t lost() const;
  // Interarrival jitter in timestamp units.
  double jitter() const { return jitter_; }

 private:
  bool started_ = false;
  int64_t base_ = 0;
  int64_t highest_ = 0;
  uint64_t received_ = 0;
  uint32_t last_transit_ = 0;
  double jitter_ = 0;
};

}  // namespace ketphone::media
