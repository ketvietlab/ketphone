#include <array>
#include <vector>

#include "check.hpp"
#include "media/rtp.hpp"

using namespace ketphone::media;

TEST(rtp_header_round_trips) {
  std::array<uint8_t, 3> payload = {1, 2, 3};
  std::array<uint8_t, 64> buffer{};
  RtpHeader header;
  header.payload_type = 8;
  header.marker = true;
  header.sequence = 0xfffe;
  header.timestamp = 0x01020304;
  header.ssrc = 0xdeadbeef;
  const size_t size = write_rtp(buffer, header, payload);
  CHECK_EQ(size, size_t{15});
  CHECK_EQ(int{buffer[0]}, 0x80);
  CHECK_EQ(int{buffer[1]}, 0x88);
  const auto packet = parse_rtp({buffer.data(), size});
  CHECK(packet.has_value());
  CHECK_EQ(packet->header.sequence, uint16_t{0xfffe});
  CHECK_EQ(packet->header.timestamp, 0x01020304u);
  CHECK_EQ(packet->header.ssrc, 0xdeadbeefu);
  CHECK(packet->header.marker);
  CHECK_EQ(packet->payload.size(), size_t{3});
  CHECK_EQ(int{packet->payload[2]}, 3);
  CHECK_EQ(write_rtp({buffer.data(), 14}, header, payload), size_t{0});
}

TEST(rtp_parse_skips_csrc_extension_and_padding) {
  // V=2, P=1, X=1, CC=1; one CSRC, a one-word extension, 2 payload bytes, 2 padding bytes.
  const std::vector<uint8_t> datagram = {0xb1, 0x08, 0x00, 0x01, 0, 0, 0, 1, 0, 0, 0, 2,  // header
                                         9,    9,    9,    9,                                // CSRC
                                         0xbe, 0xde, 0x00, 0x01, 7, 7, 7, 7,                 // extension
                                         0x42, 0x43, 0x00, 0x02};                            // payload + padding
  const auto packet = parse_rtp(datagram);
  CHECK(packet.has_value());
  CHECK_EQ(packet->payload.size(), size_t{2});
  CHECK_EQ(int{packet->payload[0]}, 0x42);
}

TEST(rtp_parse_rejects_rtcp_and_malformed_packets) {
  const std::vector<uint8_t> rtcp = {0x80, 200, 0, 6, 0, 0, 0, 1, 0, 0, 0, 0};
  CHECK(!parse_rtp(rtcp).has_value());
  const std::vector<uint8_t> version1 = {0x40, 8, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1};
  CHECK(!parse_rtp(version1).has_value());
  const std::vector<uint8_t> short_packet = {0x80, 8, 0};
  CHECK(!parse_rtp(short_packet).has_value());
  const std::vector<uint8_t> bad_padding = {0xa0, 8, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 0x05};
  CHECK(!parse_rtp(bad_padding).has_value());
}

TEST(receive_statistics_count_loss_across_the_sequence_wrap) {
  ReceiveStatistics stats;
  uint32_t arrival = 1000;
  int64_t last = 0;
  for (uint32_t i = 0; i < 20; ++i) {
    const auto sequence = static_cast<uint16_t>(65530 + i);
    if (i == 8 || i == 9) continue;  // lost
    last = stats.on_packet(sequence, i * 160, arrival + i * 160);
  }
  CHECK_EQ(stats.received(), uint64_t{18});
  CHECK_EQ(stats.lost(), uint64_t{2});
  CHECK_EQ(last, int64_t{65530 + 19});
  CHECK(stats.jitter() < 0.001);  // perfectly paced
}

// A packet from before the wrap that arrives after it belongs to the previous cycle.
TEST(receive_statistics_place_a_late_packet_behind_the_wrap) {
  ReceiveStatistics stats;
  CHECK_EQ(stats.on_packet(65534, 0, 0), int64_t{65534});
  CHECK_EQ(stats.on_packet(0, 320, 320), int64_t{65536});
  CHECK_EQ(stats.on_packet(65535, 160, 330), int64_t{65535});
  CHECK_EQ(stats.lost(), uint64_t{0});
}

TEST(receive_statistics_place_reordered_packets_and_measure_jitter) {
  ReceiveStatistics stats;
  CHECK_EQ(stats.on_packet(10, 0, 0), int64_t{10});
  CHECK_EQ(stats.on_packet(12, 320, 330), int64_t{12});
  CHECK_EQ(stats.on_packet(11, 160, 340), int64_t{11});
  CHECK_EQ(stats.lost(), uint64_t{0});
  CHECK(stats.jitter() > 0);
  // A far jump is a restarted sender, not 5000 lost packets.
  stats.on_packet(5000, 480, 500);
  CHECK_EQ(stats.lost(), uint64_t{0});
}
