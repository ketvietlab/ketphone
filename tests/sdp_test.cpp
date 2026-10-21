#include "check.hpp"
#include "sip/sdp.hpp"

using namespace ketphone::sip;
using ketphone::test::fail;

TEST(parses_an_asterisk_answer) {
  const std::string sdp =
      "v=0\r\n"
      "o=- 1 3 IN IP4 127.0.0.1\r\n"
      "s=Asterisk\r\n"
      "c=IN IP4 127.0.0.1\r\n"
      "t=0 0\r\n"
      "m=audio 10012 RTP/AVP 8 101\r\n"
      "a=rtpmap:8 PCMA/8000\r\n"
      "a=rtpmap:101 telephone-event/8000\r\n"
      "a=ptime:20\r\n"
      "a=sendrecv\r\n";
  const auto audio = parse_audio(sdp);
  CHECK(audio.has_value());
  CHECK_EQ(audio->address, std::string("127.0.0.1"));
  CHECK_EQ(audio->port, uint16_t{10012});
  CHECK(audio->offers_pcma());
  CHECK(audio->remote_sends);
}

TEST(media_level_connection_wins_and_other_streams_are_ignored) {
  const std::string sdp =
      "v=0\r\nc=IN IP4 10.0.0.1\r\n"
      "m=video 4000 RTP/AVP 96\r\nc=IN IP4 10.0.0.9\r\n"
      "m=audio 5000 RTP/AVP 0\r\nc=IN IP4 10.0.0.2\r\na=inactive\r\n";
  const auto audio = parse_audio(sdp);
  CHECK(audio.has_value());
  CHECK_EQ(audio->address, std::string("10.0.0.2"));
  CHECK_EQ(audio->port, uint16_t{5000});
  CHECK(!audio->offers_pcma());
  CHECK(!audio->remote_sends);
}

TEST(rejects_descriptions_without_usable_audio) {
  CHECK(!parse_audio("").has_value());
  CHECK(!parse_audio("v=0\r\nc=IN IP4 1.2.3.4\r\nm=video 4000 RTP/AVP 96\r\n").has_value());
  CHECK(!parse_audio("v=0\r\nm=audio 4000 RTP/AVP 8\r\n").has_value());  // no connection address
  CHECK(!parse_audio("v=0\r\nc=IN IP4 1.2.3.4\r\nm=audio 4000 UDP/TLS/RTP/SAVPF 8\r\n").has_value());
  CHECK(!parse_audio("v=0\r\nc=IN IP7 ::1\r\nm=audio 4000 RTP/AVP 8\r\n").has_value());
}

TEST(ipv6_sdp_offer_and_media_override_round_trip) {
  const std::string offer = build_audio_sdp("2001:db8::1234", 40000, 7, 2);
  CHECK(offer.find("o=- 7 2 IN IP6 2001:db8::1234\r\n") != std::string::npos);
  CHECK(offer.find("c=IN IP6 2001:db8::1234\r\n") != std::string::npos);
  const auto audio = parse_audio(offer);
  CHECK(audio.has_value());
  CHECK_EQ(audio->address, std::string("2001:db8::1234"));
  CHECK_EQ(audio->port, uint16_t{40000});
  CHECK(audio->offers_pcma());
  const auto override = parse_audio("v=0\r\nc=IN IP4 192.0.2.1\r\nm=audio 5000 RTP/AVP 8\r\nc=IN IP6 ::1\r\n");
  CHECK(override.has_value());
  CHECK_EQ(override->address, std::string("::1"));
  CHECK(!parse_audio("v=0\r\nc=IN IP4 192.0.2.1\r\nm=audio 5000 RTP/AVP 8\r\nc=IN IP7 ::1\r\n"));
  CHECK(!parse_audio("v=0\r\nc=IN IP6 \r\nm=audio 5000 RTP/AVP 8\r\n"));
  CHECK(!parse_audio("v=0\r\nc=IN IP6 [::1]\r\nm=audio 5000 RTP/AVP 8\r\n"));
}

TEST(built_offer_round_trips) {
  const std::string offer = build_audio_sdp("192.168.1.5", 40000, 7, 1);
  const auto audio = parse_audio(offer);
  CHECK(audio.has_value());
  CHECK_EQ(audio->address, std::string("192.168.1.5"));
  CHECK_EQ(audio->port, uint16_t{40000});
  CHECK_EQ(audio->payload_types.size(), size_t{2});
  CHECK(offer.find("a=rtpmap:8 PCMA/8000\r\n") != std::string::npos);
}

namespace {
// 30 bytes of key and salt, base64: the shape every SDES line here carries.
constexpr const char* kInline = "WQECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwd";
}  // namespace

TEST(parses_sdes_crypto_lines_under_either_profile) {
  for (const std::string profile : {"RTP/SAVP", "RTP/AVP"}) {
    const std::string sdp = "v=0\r\nc=IN IP4 10.0.0.1\r\nm=audio 4000 " + profile +
                            " 8\r\n"
                            "a=crypto:2 AES_CM_128_HMAC_SHA1_80 inline:" +
                            kInline + "|2^31\r\n";
    const auto audio = parse_audio(sdp);
    CHECK(audio.has_value());
    CHECK_EQ(audio->savp, profile == "RTP/SAVP");
    CHECK_EQ(audio->crypto.size(), size_t{1});
    CHECK_EQ(audio->crypto[0].tag, uint32_t{2});
    CHECK_EQ(audio->crypto[0].key.size(), kSdesKeyLength);
    CHECK_EQ(int{audio->crypto[0].key[0]}, int{'Y'});
  }
}

TEST(leaves_out_crypto_lines_this_side_cannot_use) {
  const std::string inline_key = kInline;
  const std::string lines[] = {
      "a=crypto:1 AES_CM_128_HMAC_SHA1_32 inline:" + inline_key,            // other suite
      "a=crypto:1 AES_256_CM_HMAC_SHA1_80 inline:" + inline_key,            // other suite
      "a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:" + inline_key + "|1:4",   // MKI
      "a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:" + inline_key + "|2^20|1:4",
      "a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:" + inline_key + " UNENCRYPTED_SRTP",
      "a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:" + inline_key + ";inline:" + inline_key,
      "a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:AAECAwQFBgcICQoLDA0ODxAREhMUFRYX",  // 24 bytes
      "a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:not*base64",
      "a=crypto:x AES_CM_128_HMAC_SHA1_80 inline:" + inline_key,
      "a=crypto:1 AES_CM_128_HMAC_SHA1_80 key:" + inline_key,
  };
  for (const auto& line : lines) {
    const auto audio = parse_audio("v=0\r\nc=IN IP4 10.0.0.1\r\nm=audio 4000 RTP/SAVP 8\r\n" + line + "\r\n");
    CHECK(audio.has_value());
    if (!audio->crypto.empty()) fail(__FILE__, __LINE__, "accepted " + line);
  }
}

TEST(built_secure_offer_round_trips_its_key) {
  std::vector<uint8_t> key(kSdesKeyLength);
  for (size_t n = 0; n < key.size(); ++n) key[n] = static_cast<uint8_t>(n * 7);
  const std::string offer = build_audio_sdp("192.168.1.5", 40000, 7, 1, LocalCrypto{true, 3, key});
  CHECK(offer.find("m=audio 40000 RTP/SAVP 8 101\r\n") != std::string::npos);
  CHECK(offer.find("a=crypto:3 AES_CM_128_HMAC_SHA1_80 inline:") != std::string::npos);
  const auto audio = parse_audio(offer);
  CHECK(audio.has_value());
  CHECK(audio->savp);
  CHECK_EQ(audio->crypto.size(), size_t{1});
  CHECK_EQ(audio->crypto[0].tag, uint32_t{3});
  CHECK(audio->crypto[0].key == key);
  const std::string answer = build_audio_sdp("192.168.1.5", 40000, 7, 1, LocalCrypto{false, 1, key});
  CHECK(answer.find("m=audio 40000 RTP/AVP 8 101\r\n") != std::string::npos);
  CHECK(build_audio_sdp("192.168.1.5", 40000, 7, 1).find("a=crypto") == std::string::npos);
}
