#pragma once

#include <optional>
#include <string>
#include <string_view>

namespace ketphone::sip {

// A WWW-Authenticate or Proxy-Authenticate challenge (RFC 2617 / RFC 3261 section 22).
struct Challenge {
  std::string realm;
  std::string nonce;
  std::string opaque;
  std::string algorithm;
  // True when the server offers qop=auth; auth-int is not supported.
  bool qop_auth = false;
};

std::optional<Challenge> parse_challenge(std::string_view header_value);

struct Credentials {
  std::string username;
  std::string password;
};

// The request-digest from RFC 2617 section 3.2.2.1. With qop, nc and cnonce are part of it.
std::string digest_response(const Credentials& credentials, const Challenge& challenge,
                            std::string_view method, std::string_view uri, std::string_view nc,
                            std::string_view cnonce);

// The full Authorization or Proxy-Authorization header value, generating a cnonce when the
// challenge uses qop. Returns nothing for algorithms other than MD5.
std::optional<std::string> authorization_value(const Credentials& credentials, const Challenge& challenge,
                                               std::string_view method, std::string_view uri);

}  // namespace ketphone::sip
