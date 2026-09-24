#pragma once

#include <string>
#include <string_view>

namespace ketphone::sip {

// Lowercase hex MD5 of the input. Only for SIP digest authentication (RFC 2617), which mandates
// MD5; never use it for anything that needs a secure hash.
std::string md5_hex(std::string_view input);

}  // namespace ketphone::sip
