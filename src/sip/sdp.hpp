#pragma once

#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace ketphone::sip {

// RTP payload type of G.711 A-law (PCMA), fixed by RFC 3551.
inline constexpr uint8_t kPayloadPcma = 8;
// Payload type this side offers for RFC 4733 telephone events.
inline constexpr uint8_t kPayloadTelephoneEvent = 101;

// The one SDES crypto suite (RFC 4568) this side offers and accepts.
inline constexpr std::string_view kSdesSuite = "AES_CM_128_HMAC_SHA1_80";
// Its inline key: 16 bytes of master key followed by 14 of master salt.
inline constexpr size_t kSdesKeyLength = 30;

// An a=crypto line this side can use: kSdesSuite, one inline key of the right length, no MKI and
// no session parameters. A lifetime is accepted and ignored: calls end long before 2^20 packets.
struct SdesCrypto {
  uint32_t tag = 0;
  std::vector<uint8_t> key;
};

// The audio stream of a session description; video and other media are ignored.
struct AudioDescription {
  std::string address;
  uint16_t port = 0;
  std::vector<uint8_t> payload_types;
  // False for a=inactive or a=recvonly from the other side (it will not send to us), which is
  // how a hold would arrive.
  bool remote_sends = true;
  // The m= line's profile is RTP/SAVP rather than RTP/AVP. Asterisk's optimistic SRTP offers keys
  // under RTP/AVP, so the keys below matter more than the profile.
  bool savp = false;
  // Usable a=crypto lines in the order they appeared; lines this side cannot use are left out.
  std::vector<SdesCrypto> crypto;

  bool offers_pcma() const;
};

// Parses the first m=audio line and its connection address (media-level c= wins over
// session-level). Returns nothing when there is no usable audio stream, including one whose
// profile is neither RTP/AVP nor RTP/SAVP (DTLS-SRTP, for instance).
std::optional<AudioDescription> parse_audio(std::string_view sdp);

// The SRTP part of an offer or answer: the profile to put on the m= line and the one crypto line.
struct LocalCrypto {
  bool savp = true;
  uint32_t tag = 1;
  std::span<const uint8_t> key;
};

// Offer or answer for one A-law audio stream plus telephone events, ptime 20 ms, with a crypto
// line when `crypto` is given.
std::string build_audio_sdp(std::string_view address, uint16_t port, uint64_t session_id, uint64_t version,
                            const std::optional<LocalCrypto>& crypto = std::nullopt);

}  // namespace ketphone::sip
