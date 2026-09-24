#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace ketphone::sip {

// RTP payload type of G.711 A-law (PCMA), fixed by RFC 3551.
inline constexpr uint8_t kPayloadPcma = 8;
// Payload type this side offers for RFC 4733 telephone events.
inline constexpr uint8_t kPayloadTelephoneEvent = 101;

// The audio stream of a session description; video and other media are ignored.
struct AudioDescription {
  std::string address;
  uint16_t port = 0;
  std::vector<uint8_t> payload_types;
  // False for a=inactive or a=recvonly from the other side (it will not send to us), which is
  // how a hold would arrive.
  bool remote_sends = true;

  bool offers_pcma() const;
};

// Parses the first m=audio line and its connection address (media-level c= wins over
// session-level). Returns nothing when there is no usable audio stream.
std::optional<AudioDescription> parse_audio(std::string_view sdp);

// Offer or answer for one A-law audio stream plus telephone events, ptime 20 ms.
std::string build_audio_sdp(std::string_view address, uint16_t port, uint64_t session_id, uint64_t version);

}  // namespace ketphone::sip
