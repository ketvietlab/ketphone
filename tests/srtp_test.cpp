#include <algorithm>
#include <array>

#include "check.hpp"
#include "media/srtp.hpp"

using namespace ketphone::media;

namespace {

// RFC 3711 AES_CM_128_HMAC_SHA1_80 known answer from libsrtp's own driver (test/srtp_driver.c,
// srtp_validate): key and salt, an RTP packet, and what it must become.
constexpr SrtpKey kKey = {0xe1, 0xf9, 0x7a, 0x0d, 0x3e, 0x01, 0x8b, 0xe0, 0xd6, 0x4f, 0xa3, 0x2c, 0x06, 0xde, 0x41,
                          0x39, 0x0e, 0xc6, 0x75, 0xad, 0x49, 0x8a, 0xfe, 0xeb, 0xb6, 0x96, 0x0b, 0x3a, 0xab, 0xe6};
constexpr std::array<uint8_t, 28> kPlain = {0x80, 0x0f, 0x12, 0x34, 0xde, 0xca, 0xfb, 0xad, 0xca, 0xfe,
                                            0xba, 0xbe, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab,
                                            0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab, 0xab};
constexpr std::array<uint8_t, 38> kCipher = {0x80, 0x0f, 0x12, 0x34, 0xde, 0xca, 0xfb, 0xad, 0xca, 0xfe,
                                             0xba, 0xbe, 0x4e, 0x55, 0xdc, 0x4c, 0xe7, 0x99, 0x78, 0xd8,
                                             0x8c, 0xa4, 0xd2, 0x15, 0x94, 0x9d, 0x24, 0x02, 0xb7, 0x8d,
                                             0x6a, 0xcc, 0x99, 0xea, 0x17, 0x9b, 0x8d, 0xbb};

struct Packet {
  alignas(4) std::array<uint8_t, 28 + kSrtpTrailerRoom> bytes{};
  size_t size = 0;
};

Packet plain_packet(uint16_t sequence = 0x1234) {
  Packet packet;
  std::copy(kPlain.begin(), kPlain.end(), packet.bytes.begin());
  packet.bytes[2] = static_cast<uint8_t>(sequence >> 8);
  packet.bytes[3] = static_cast<uint8_t>(sequence);
  packet.size = kPlain.size();
  return packet;
}

Packet cipher_packet() {
  Packet packet;
  std::copy(kCipher.begin(), kCipher.end(), packet.bytes.begin());
  packet.size = kCipher.size();
  return packet;
}

}  // namespace

TEST(srtp_protects_to_the_rfc_3711_known_answer) {
  auto out = SrtpStream::create(SrtpStream::Direction::Outbound, kKey);
  CHECK(out != nullptr);
  auto packet = plain_packet();
  CHECK_EQ(out->protect(packet.bytes, packet.size), kCipher.size());
  CHECK(std::equal(kCipher.begin(), kCipher.end(), packet.bytes.begin()));
}

TEST(srtp_unprotects_the_known_answer_once) {
  auto in = SrtpStream::create(SrtpStream::Direction::Inbound, kKey);
  CHECK(in != nullptr);
  auto packet = cipher_packet();
  const auto size = in->unprotect(packet.bytes, packet.size);
  CHECK(size.has_value());
  CHECK_EQ(*size, kPlain.size());
  CHECK(std::equal(kPlain.begin(), kPlain.end(), packet.bytes.begin()));
  auto replay = cipher_packet();
  CHECK(!in->unprotect(replay.bytes, replay.size).has_value());
}

TEST(srtp_refuses_tampered_foreign_and_plain_packets) {
  for (const size_t at : {size_t{1}, size_t{13}, size_t{37}}) {  // header, payload, tag
    auto in = SrtpStream::create(SrtpStream::Direction::Inbound, kKey);
    auto packet = cipher_packet();
    packet.bytes[at] ^= 0x01;
    CHECK(!in->unprotect(packet.bytes, packet.size).has_value());
  }
  SrtpKey other = kKey;
  other[0] ^= 0x80;
  auto foreign = SrtpStream::create(SrtpStream::Direction::Inbound, other);
  auto packet = cipher_packet();
  CHECK(!foreign->unprotect(packet.bytes, packet.size).has_value());
  auto in = SrtpStream::create(SrtpStream::Direction::Inbound, kKey);
  auto plain = plain_packet();
  CHECK(!in->unprotect(plain.bytes, plain.size).has_value());  // RTP without a tag
  CHECK(!in->unprotect(plain.bytes, 12).has_value());
}

TEST(srtp_round_trips_a_stream_with_any_ssrc) {
  const auto key = generate_srtp_key();
  CHECK(key.has_value());
  CHECK(*key != SrtpKey{});
  auto out = SrtpStream::create(SrtpStream::Direction::Outbound, *key);
  auto in = SrtpStream::create(SrtpStream::Direction::Inbound, *key);
  CHECK_EQ(out->key() == *key, true);
  for (uint16_t sequence = 100; sequence < 110; ++sequence) {
    auto packet = plain_packet(sequence);
    if (sequence >= 105) packet.bytes[8] = 0x11;  // the far end changed its SSRC midway
    const auto sent = out->protect(packet.bytes, packet.size);
    CHECK_EQ(sent, kPlain.size() + 10);
    const auto received = in->unprotect(packet.bytes, sent);
    CHECK(received.has_value());
    CHECK_EQ(*received, kPlain.size());
    CHECK_EQ(int{packet.bytes[3]}, int{static_cast<uint8_t>(sequence)});
  }
}

TEST(srtp_refuses_misaligned_or_short_buffers) {
  auto out = SrtpStream::create(SrtpStream::Direction::Outbound, kKey);
  alignas(4) std::array<uint8_t, 28 + kSrtpTrailerRoom + 1> storage{};
  std::copy(kPlain.begin(), kPlain.end(), storage.begin() + 1);
  CHECK_EQ(out->protect(std::span<uint8_t>(storage).subspan(1), kPlain.size()), size_t{0});
  Packet packet = plain_packet();
  CHECK_EQ(out->protect(std::span<uint8_t>(packet.bytes).first(28 + 9), packet.size), size_t{0});
}
