#include "sip/sdp.hpp"

#include <algorithm>

#include "sip/base64.hpp"
#include "sip/text.hpp"

namespace ketphone::sip {
namespace {

// Connection addresses in SDP have no SIP URI brackets. A multicast suffix is not
// part of the address handed to the system resolver.
std::optional<std::string> connection_address(std::string_view value) {
  if (!value.starts_with("IN IP4 ") && !value.starts_with("IN IP6 ")) return std::nullopt;
  std::string_view address = trim(value.substr(7));
  address = address.substr(0, address.find('/'));  // multicast TTL
  if (address.empty() || address.find_first_of(" \t\r\n[]") != std::string_view::npos) return std::nullopt;
  return std::string(address);
}

// "1 AES_CM_128_HMAC_SHA1_80 inline:KEY[|lifetime]" from an a=crypto: line. Anything this side
// cannot honour gives nothing: another suite, several keys, an MKI or any session parameter.
std::optional<SdesCrypto> parse_crypto(std::string_view value) {
  const size_t tag_end = value.find(' ');
  if (tag_end == std::string_view::npos) return std::nullopt;
  const auto tag = parse_integer<uint32_t>(value.substr(0, tag_end));
  if (!tag || *tag > 999999999) return std::nullopt;
  std::string_view rest = trim(value.substr(tag_end + 1));
  const size_t suite_end = rest.find(' ');
  if (suite_end == std::string_view::npos || rest.substr(0, suite_end) != kSdesSuite) return std::nullopt;
  rest = trim(rest.substr(suite_end + 1));
  if (rest.find_first_of(" \t;") != std::string_view::npos) return std::nullopt;
  if (!rest.starts_with("inline:")) return std::nullopt;
  rest.remove_prefix(7);
  const size_t key_end = rest.find('|');
  if (key_end != std::string_view::npos) {
    // Only a lifetime may follow; an MKI ("value:length") is not supported.
    const std::string_view parameters = rest.substr(key_end + 1);
    if (parameters.empty() || parameters.find_first_of("|:") != std::string_view::npos) return std::nullopt;
  }
  auto key = base64_decode(rest.substr(0, key_end));
  if (!key || key->size() != kSdesKeyLength) return std::nullopt;
  return SdesCrypto{*tag, std::move(*key)};
}

}  // namespace

bool AudioDescription::offers_pcma() const {
  return std::find(payload_types.begin(), payload_types.end(), kPayloadPcma) != payload_types.end();
}

std::optional<AudioDescription> parse_audio(std::string_view sdp) {
  std::optional<std::string> session_address;
  std::optional<AudioDescription> audio;
  std::optional<std::string> media_address;
  bool has_media_connection = false;
  bool in_audio = false;
  bool seen_audio = false;

  for (const std::string_view line : split_lines(sdp)) {
    if (line.size() < 2 || line[1] != '=') continue;
    const char type = line[0];
    const std::string_view value = line.substr(2);
    if (type == 'm') {
      if (seen_audio) break;  // only the first audio stream matters
      in_audio = value.starts_with("audio ");
      if (!in_audio) continue;
      seen_audio = true;
      std::string_view rest = value.substr(6);
      const size_t port_end = rest.find(' ');
      const auto port = parse_integer<uint16_t>(rest.substr(0, port_end));
      if (!port || port_end == std::string_view::npos) return std::nullopt;
      rest.remove_prefix(port_end + 1);
      const size_t proto_end = rest.find(' ');
      const std::string_view profile = rest.substr(0, proto_end);
      if (profile != "RTP/AVP" && profile != "RTP/SAVP") return std::nullopt;
      audio = AudioDescription{};
      audio->port = *port;
      audio->savp = profile == "RTP/SAVP";
      rest.remove_prefix(proto_end == std::string_view::npos ? rest.size() : proto_end + 1);
      while (!rest.empty()) {
        const size_t space = rest.find(' ');
        if (const auto payload = parse_integer<uint8_t>(rest.substr(0, space))) audio->payload_types.push_back(*payload);
        rest.remove_prefix(space == std::string_view::npos ? rest.size() : space + 1);
      }
    } else if (type == 'c') {
      if (in_audio) {
        has_media_connection = true;
        media_address = connection_address(value);
      } else if (!seen_audio) {
        session_address = connection_address(value);
      }
    } else if (type == 'a' && in_audio && audio) {
      if (value == "inactive" || value == "recvonly") audio->remote_sends = false;
      if (value.starts_with("crypto:")) {
        if (auto crypto = parse_crypto(value.substr(7))) audio->crypto.push_back(std::move(*crypto));
      }
    }
  }

  if (!audio || audio->port == 0) return std::nullopt;
  if (has_media_connection && !media_address) return std::nullopt;
  if (media_address) {
    audio->address = *media_address;
  } else if (session_address) {
    audio->address = *session_address;
  } else {
    return std::nullopt;
  }
  return audio;
}

std::string build_audio_sdp(std::string_view address, uint16_t port, uint64_t session_id, uint64_t version,
                            const std::optional<LocalCrypto>& crypto) {
  const std::string ip(address);
  const std::string family = ip.find(':') == std::string::npos ? "IP4" : "IP6";
  const std::string payloads = std::to_string(kPayloadPcma) + " " + std::to_string(kPayloadTelephoneEvent);
  const std::string event = std::to_string(kPayloadTelephoneEvent);
  const std::string profile = crypto && crypto->savp ? "RTP/SAVP" : "RTP/AVP";
  std::string keys;
  if (crypto) {
    keys = "a=crypto:" + std::to_string(crypto->tag) + " " + std::string(kSdesSuite) +
           " inline:" + base64_encode(crypto->key) + "\r\n";
  }
  return "v=0\r\n"
         "o=- " + std::to_string(session_id) + " " + std::to_string(version) + " IN " + family + " " + ip + "\r\n"
         "s=KetPhone\r\n"
         "c=IN " + family + " " + ip + "\r\n"
         "t=0 0\r\n"
         "m=audio " + std::to_string(port) + " " + profile + " " + payloads + "\r\n"
         "a=rtpmap:8 PCMA/8000\r\n"
         "a=rtpmap:" + event + " telephone-event/8000\r\n"
         "a=fmtp:" + event + " 0-16\r\n"
         "a=ptime:20\r\n"
         "a=sendrecv\r\n" + keys;
}

}  // namespace ketphone::sip
