#pragma once

#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace ketphone::sip {

// Standard base64 (RFC 4648 section 4) with padding, as SDES keys (RFC 4568) and PEM use it.
std::string base64_encode(std::span<const uint8_t> data);

// Decodes standard base64. Padding is optional; anything else outside the alphabet, or a length
// that cannot come from encoding, gives nothing.
std::optional<std::vector<uint8_t>> base64_decode(std::string_view text);

}  // namespace ketphone::sip
