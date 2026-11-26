// RFC 4733 events and hold in the media session, packet by packet.
#include <array>
#include <cstdint>
#include <optional>
#include <vector>

#include "check.hpp"
#include "media/g711.hpp"
#include "media/media_session.hpp"
#include "media/rtp.hpp"
#include "media/spsc_ring.hpp"

using namespace ketphone::media;

namespace {

struct Event {
  RtpHeader header;
  uint8_t code = 0;
  bool end = false;
  uint8_t volume = 0;
  uint16_t duration = 0;
  bool audio = false;
};

struct Session {
  SpscRing<int16_t> capture{1600};
  SpscRing<int16_t> playout{1600};
  MediaSession media{capture, playout, 40000};

  Session() {
    media.start(0x1111, 1000, 5000);
    media.set_telephone_event(101);
  }

  // The next packet, decoded; nothing when none was sent.
  std::optional<Event> next() {
    std::array<uint8_t, kMaxPacketSize> buffer{};
    const size_t size = media.next_packet(buffer);
    if (size == 0) return std::nullopt;
    const auto packet = parse_rtp(std::span<const uint8_t>(buffer).first(size));
    CHECK(packet.has_value());
    Event out;
    out.header = packet->header;
    if (packet->header.payload_type == 8) {
      out.audio = true;
      CHECK_EQ(packet->payload.size(), size_t{160});
      return out;
    }
    CHECK_EQ(packet->payload.size(), size_t{4});
    out.code = packet->payload[0];
    out.end = (packet->payload[1] & 0x80) != 0;
    out.volume = packet->payload[1] & 0x3f;
    out.duration = static_cast<uint16_t>(packet->payload[2] << 8 | packet->payload[3]);
    return out;
  }
};

std::vector<uint8_t> rtp(uint8_t payload_type, uint16_t sequence, uint32_t timestamp, size_t size) {
  std::vector<uint8_t> payload(size, 0x55);
  RtpHeader header;
  header.payload_type = payload_type;
  header.sequence = sequence;
  header.timestamp = timestamp;
  header.ssrc = 0x2222;
  std::vector<uint8_t> packet(kRtpHeaderSize + size);
  write_rtp(packet, header, payload);
  return packet;
}

}  // namespace

TEST(event_codes_cover_the_sixteen_keys) {
  CHECK(dtmf_event_code('0') == std::optional<uint8_t>(0));
  CHECK(dtmf_event_code('9') == std::optional<uint8_t>(9));
  CHECK(dtmf_event_code('*') == std::optional<uint8_t>(10));
  CHECK(dtmf_event_code('#') == std::optional<uint8_t>(11));
  CHECK(dtmf_event_code('A') == std::optional<uint8_t>(12));
  CHECK(dtmf_event_code('d') == std::optional<uint8_t>(15));
  CHECK(!dtmf_event_code('E'));
  CHECK(!dtmf_event_code(' '));
}

TEST(a_key_is_sent_as_one_event_with_growing_duration_and_three_end_packets) {
  Session session;
  const auto first_audio = session.next();
  CHECK(first_audio->audio);
  CHECK(session.media.queue_dtmf("5", 100));  // 100 ms: five packets of 20 ms

  std::vector<Event> packets;
  // Five packets of the key, the fifth the first end packet, then two more end packets.
  for (int i = 0; i < 7; ++i) packets.push_back(*session.next());
  for (size_t i = 0; i < packets.size(); ++i) {
    const Event& event = packets[i];
    CHECK(!event.audio);
    CHECK_EQ(int{event.header.payload_type}, 101);
    CHECK_EQ(int{event.code}, 5);
    CHECK_EQ(int{event.volume}, int{kDtmfVolume});
    CHECK_EQ(event.header.ssrc, uint32_t{0x1111});
    // One event, one timestamp: where it began.
    CHECK_EQ(event.header.timestamp, first_audio->header.timestamp + 160);
    CHECK_EQ(event.header.sequence, static_cast<uint16_t>(first_audio->header.sequence + 1 + i));
    CHECK_EQ(event.header.marker, i == 0);
    const uint16_t expected = static_cast<uint16_t>(std::min<size_t>(i + 1, 5) * 160);
    CHECK_EQ(event.duration, expected);
    CHECK_EQ(event.end, i >= 4);
  }
  // Audio again, on the clock as if it had never stopped, as a new talkspurt.
  const auto after = session.next();
  CHECK(after->audio);
  CHECK(after->header.marker);
  CHECK_EQ(after->header.sequence, static_cast<uint16_t>(first_audio->header.sequence + 8));
  CHECK_EQ(after->header.timestamp, first_audio->header.timestamp + 8 * 160);
  CHECK(!session.media.dtmf_pending());
}

TEST(keys_queue_with_a_gap_of_audio_between_them) {
  Session session;
  CHECK(session.media.queue_dtmf("1#", 40));  // two packets each
  std::vector<Event> packets;
  for (int i = 0; i < 4 + 3 + 4; ++i) packets.push_back(*session.next());
  // "1": two packets, the second the first end packet, then two more end packets.
  for (int i = 0; i < 4; ++i) {
    CHECK(!packets[static_cast<size_t>(i)].audio);
    CHECK_EQ(int{packets[static_cast<size_t>(i)].code}, 1);
  }
  for (int i = 4; i < 7; ++i) CHECK(packets[static_cast<size_t>(i)].audio);
  for (int i = 7; i < 11; ++i) {
    CHECK(!packets[static_cast<size_t>(i)].audio);
    CHECK_EQ(int{packets[static_cast<size_t>(i)].code}, 11);
  }
  CHECK(packets[7].header.marker);
  CHECK(packets[7].header.timestamp != packets[0].header.timestamp);
  CHECK(session.next()->audio);
}

TEST(durations_round_up_to_whole_packets_and_are_clamped) {
  {
    Session session;
    CHECK(session.media.queue_dtmf("0", 0));  // the default, 160 ms
    uint16_t last = 0;
    for (int i = 0; i < 8 + 2; ++i) last = session.next()->duration;
    CHECK_EQ(last, uint16_t{1280});
  }
  {
    Session session;
    CHECK(session.media.queue_dtmf("0", 1));  // at least 40 ms
    session.next();
    const auto end = session.next();
    CHECK(end->end);
    CHECK_EQ(end->duration, uint16_t{320});
  }
  {
    Session session;
    CHECK(session.media.queue_dtmf("0", 50));  // 50 ms is three packets
    session.next();
    session.next();
    const auto end = session.next();
    CHECK(end->end);
    CHECK_EQ(end->duration, uint16_t{480});
  }
  {
    Session session;
    CHECK(session.media.queue_dtmf("0", 60000));  // at most 5 s
    uint16_t last = 0;
    for (int i = 0; i < 250; ++i) last = session.next()->duration;
    CHECK_EQ(last, uint16_t{40000});
    CHECK(session.next()->end);
  }
}

TEST(keys_are_refused_without_a_type_on_hold_or_when_unknown) {
  Session session;
  CHECK(!session.media.queue_dtmf("1x", 100));
  CHECK(!session.media.dtmf_pending());  // nothing of a bad string is queued
  CHECK(!session.media.queue_dtmf("", 100));
  session.media.set_telephone_event(std::nullopt);
  CHECK(!session.media.queue_dtmf("1", 100));
  session.media.set_telephone_event(101);
  session.media.set_direction(false, false);
  CHECK(!session.media.queue_dtmf("1", 100));
}

TEST(a_new_telephone_event_type_drops_queued_keys_and_uses_the_new_one) {
  Session session;
  CHECK(session.media.queue_dtmf("12", 100));
  session.next();
  session.media.set_telephone_event(96);
  CHECK(!session.media.dtmf_pending());
  CHECK(session.next()->audio);
  CHECK(session.media.queue_dtmf("3", 40));
  CHECK_EQ(int{session.next()->header.payload_type}, 96);
}

TEST(hold_sends_nothing_keeps_the_clock_and_drops_keys_in_flight) {
  Session session;
  const auto before = session.next();
  CHECK(session.media.queue_dtmf("9", 1000));
  session.next();
  session.media.set_direction(false, false);
  CHECK(!session.media.dtmf_pending());
  for (int i = 0; i < 5; ++i) CHECK(!session.next().has_value());
  session.media.set_direction(true, true);
  const auto after = session.next();
  CHECK(after->audio);
  CHECK(after->header.marker);
  // One event packet went out; the sequence goes on from it while the clock went on all along.
  CHECK_EQ(after->header.sequence, static_cast<uint16_t>(before->header.sequence + 2));
  CHECK_EQ(after->header.timestamp, before->header.timestamp + 7 * 160);
}

TEST(the_microphone_is_drained_while_held) {
  Session session;
  std::array<int16_t, 160> loud{};
  loud.fill(12000);
  session.media.set_direction(false, false);
  session.capture.push(loud.data(), loud.size());
  CHECK(!session.next().has_value());
  session.media.set_direction(true, true);
  // What was said during the hold is not sent after it.
  std::array<uint8_t, kMaxPacketSize> buffer{};
  const size_t size = session.media.next_packet(buffer);
  const auto packet = parse_rtp(std::span<const uint8_t>(buffer).first(size));
  std::array<int16_t, 160> decoded{};
  alaw_decode(packet->payload.data(), packet->payload.size(), decoded.data());
  for (const int16_t sample : decoded) CHECK(sample > -100 && sample < 100);
}

TEST(incoming_events_and_other_types_are_never_played_as_audio) {
  Session session;
  int64_t now = 1000000;
  // A long stream of telephone events and comfort noise only.
  for (uint16_t i = 0; i < 20; ++i) {
    session.media.on_packet(rtp(101, i, 160, 4), now);
    session.media.on_packet(rtp(13, static_cast<uint16_t>(100 + i), 160u * i, 1), now);
    session.media.play_frame(now);
    now += 20000;
  }
  CHECK_EQ(session.media.stats().packets_received, uint64_t{0});
  std::array<int16_t, 160> out{};
  while (session.playout.pop(out.data(), out.size()) > 0) {
    for (const int16_t sample : out) CHECK_EQ(sample, int16_t{0});
  }
}

TEST(nothing_received_is_played_while_held) {
  Session session;
  session.media.set_direction(false, false);
  int64_t now = 1000000;
  for (uint16_t i = 0; i < 10; ++i) {
    session.media.on_packet(rtp(8, i, 160u * i, 160), now);
    now += 20000;
  }
  CHECK_EQ(session.media.stats().packets_received, uint64_t{0});
  session.media.set_direction(true, true);
  for (uint16_t i = 10; i < 20; ++i) {
    session.media.on_packet(rtp(8, i, 160u * i, 160), now);
    now += 20000;
  }
  CHECK_EQ(session.media.stats().packets_received, uint64_t{10});
}
