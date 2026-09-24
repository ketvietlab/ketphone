#include "check.hpp"
#include "sip/sdp.hpp"

using namespace ketphone::sip;

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
  CHECK(!parse_audio("v=0\r\nc=IN IP4 1.2.3.4\r\nm=audio 4000 RTP/SAVP 8\r\n").has_value());
  CHECK(!parse_audio("v=0\r\nc=IN IP6 ::1\r\nm=audio 4000 RTP/AVP 8\r\n").has_value());
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
