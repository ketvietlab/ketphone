#include "media/rtp.hpp"

#include <cstdlib>
#include <cstring>

namespace ketphone::media {
namespace {

// A jump larger than this is a restarted stream rather than loss (RFC 3550 MAX_DROPOUT).
constexpr int64_t kMaxDropout = 3000;

uint16_t read16(const uint8_t* p) { return static_cast<uint16_t>((p[0] << 8) | p[1]); }
uint32_t read32(const uint8_t* p) {
  return (uint32_t{p[0]} << 24) | (uint32_t{p[1]} << 16) | (uint32_t{p[2]} << 8) | uint32_t{p[3]};
}

}  // namespace

size_t write_rtp(std::span<uint8_t> out, const RtpHeader& header, std::span<const uint8_t> payload) {
  const size_t size = kRtpHeaderSize + payload.size();
  if (out.size() < size) return 0;
  out[0] = 0x80;
  out[1] = static_cast<uint8_t>((header.marker ? 0x80 : 0) | (header.payload_type & 0x7f));
  out[2] = static_cast<uint8_t>(header.sequence >> 8);
  out[3] = static_cast<uint8_t>(header.sequence);
  for (size_t i = 0; i < 4; ++i) {
    out[4 + i] = static_cast<uint8_t>(header.timestamp >> (24 - 8 * i));
    out[8 + i] = static_cast<uint8_t>(header.ssrc >> (24 - 8 * i));
  }
  if (!payload.empty()) std::memcpy(out.data() + kRtpHeaderSize, payload.data(), payload.size());
  return size;
}

std::optional<RtpPacket> parse_rtp(std::span<const uint8_t> datagram) {
  if (datagram.size() < kRtpHeaderSize) return std::nullopt;
  const uint8_t* p = datagram.data();
  if ((p[0] >> 6) != 2) return std::nullopt;
  const uint8_t second = p[1];
  if (second >= 200 && second <= 204) return std::nullopt;  // RTCP multiplexed on the same port

  size_t offset = kRtpHeaderSize + size_t{4} * (p[0] & 0x0f);
  if (p[0] & 0x10) {
    if (datagram.size() < offset + 4) return std::nullopt;
    offset += 4 + size_t{4} * read16(p + offset + 2);
  }
  size_t end = datagram.size();
  if (p[0] & 0x20) {
    const uint8_t padding = p[end - 1];
    if (padding == 0 || padding > end - offset) return std::nullopt;
    end -= padding;
  }
  if (offset > end) return std::nullopt;

  RtpPacket packet;
  packet.header.marker = (second & 0x80) != 0;
  packet.header.payload_type = second & 0x7f;
  packet.header.sequence = read16(p + 2);
  packet.header.timestamp = read32(p + 4);
  packet.header.ssrc = read32(p + 8);
  packet.payload = datagram.subspan(offset, end - offset);
  return packet;
}

int64_t ReceiveStatistics::on_packet(uint16_t sequence, uint32_t timestamp, uint32_t arrival) {
  int64_t extended;
  if (!started_) {
    started_ = true;
    extended = sequence;
    base_ = extended;
    highest_ = extended;
  } else {
    // Place the sequence number in the 65536-wide window closest to the highest seen so far.
    const int64_t cycle = highest_ & ~int64_t{0xffff};
    extended = cycle + sequence;
    if (extended - highest_ > 32768) extended -= 65536;
    if (highest_ - extended > 32768) extended += 65536;
    if (std::llabs(extended - highest_) > kMaxDropout) {
      // The sender restarted its sequence; start counting again from here.
      base_ = extended;
      highest_ = extended;
      received_ = 0;
    } else if (extended > highest_) {
      highest_ = extended;
    }
  }
  ++received_;

  const uint32_t transit = arrival - timestamp;
  if (received_ > 1) {
    const auto delta = static_cast<int32_t>(transit - last_transit_);
    jitter_ += (std::abs(static_cast<double>(delta)) - jitter_) / 16.0;
  }
  last_transit_ = transit;
  return extended;
}

uint64_t ReceiveStatistics::lost() const {
  if (!started_) return 0;
  const int64_t expected = highest_ - base_ + 1;
  const auto received = static_cast<int64_t>(received_);
  return expected > received ? static_cast<uint64_t>(expected - received) : 0;
}

}  // namespace ketphone::media
