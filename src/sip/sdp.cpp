#include "sip/sdp.hpp"

#include <algorithm>

#include "sip/text.hpp"

namespace ketphone::sip {
namespace {

// "IN IP4 10.0.0.1" gives 10.0.0.1; IPv6 is not supported.
std::optional<std::string> connection_address(std::string_view value) {
  if (!value.starts_with("IN IP4 ")) return std::nullopt;
  std::string_view address = trim(value.substr(7));
  address = address.substr(0, address.find('/'));  // multicast TTL
  return std::string(address);
}

}  // namespace

bool AudioDescription::offers_pcma() const {
  return std::find(payload_types.begin(), payload_types.end(), kPayloadPcma) != payload_types.end();
}

std::optional<AudioDescription> parse_audio(std::string_view sdp) {
  std::optional<std::string> session_address;
  std::optional<AudioDescription> audio;
  std::optional<std::string> media_address;
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
      if (rest.substr(0, proto_end) != "RTP/AVP") return std::nullopt;
      audio = AudioDescription{};
      audio->port = *port;
      rest.remove_prefix(proto_end == std::string_view::npos ? rest.size() : proto_end + 1);
      while (!rest.empty()) {
        const size_t space = rest.find(' ');
        if (const auto payload = parse_integer<uint8_t>(rest.substr(0, space))) audio->payload_types.push_back(*payload);
        rest.remove_prefix(space == std::string_view::npos ? rest.size() : space + 1);
      }
    } else if (type == 'c') {
      if (in_audio) {
        media_address = connection_address(value);
      } else if (!seen_audio) {
        session_address = connection_address(value);
      }
    } else if (type == 'a' && in_audio && audio) {
      if (value == "inactive" || value == "recvonly") audio->remote_sends = false;
    }
  }

  if (!audio || audio->port == 0) return std::nullopt;
  if (media_address) {
    audio->address = *media_address;
  } else if (session_address) {
    audio->address = *session_address;
  } else {
    return std::nullopt;
  }
  return audio;
}

std::string build_audio_sdp(std::string_view address, uint16_t port, uint64_t session_id, uint64_t version) {
  const std::string ip(address);
  const std::string payloads = std::to_string(kPayloadPcma) + " " + std::to_string(kPayloadTelephoneEvent);
  const std::string event = std::to_string(kPayloadTelephoneEvent);
  return "v=0\r\n"
         "o=- " + std::to_string(session_id) + " " + std::to_string(version) + " IN IP4 " + ip + "\r\n"
         "s=KetPhone\r\n"
         "c=IN IP4 " + ip + "\r\n"
         "t=0 0\r\n"
         "m=audio " + std::to_string(port) + " RTP/AVP " + payloads + "\r\n"
         "a=rtpmap:8 PCMA/8000\r\n"
         "a=rtpmap:" + event + " telephone-event/8000\r\n"
         "a=fmtp:" + event + " 0-16\r\n"
         "a=ptime:20\r\n"
         "a=sendrecv\r\n";
}

}  // namespace ketphone::sip
