#include "sip/digest.hpp"

#include "sip/md5.hpp"
#include "sip/random.hpp"
#include "sip/text.hpp"

namespace ketphone::sip {
namespace {

std::string join(std::initializer_list<std::string_view> parts) {
  std::string out;
  for (auto part : parts) {
    if (!out.empty()) out += ':';
    out += part;
  }
  return out;
}

}  // namespace

std::optional<Challenge> parse_challenge(std::string_view value) {
  value = trim(value);
  if (value.size() < 7 || !iequals(value.substr(0, 6), "Digest")) return std::nullopt;
  value.remove_prefix(6);

  Challenge challenge;
  bool has_nonce = false;
  while (!value.empty()) {
    value = trim(value);
    while (!value.empty() && value.front() == ',') value = trim(value.substr(1));
    const size_t equals = value.find('=');
    if (equals == std::string_view::npos) break;
    const std::string key = lowercase(trim(value.substr(0, equals)));
    value.remove_prefix(equals + 1);
    value = trim(value);
    std::string parsed;
    if (!value.empty() && value.front() == '"') {
      size_t i = 1;
      for (; i < value.size() && value[i] != '"'; ++i) {
        if (value[i] == '\\' && i + 1 < value.size()) ++i;
        parsed.push_back(value[i]);
      }
      value.remove_prefix(i < value.size() ? i + 1 : value.size());
    } else {
      const size_t end = value.find(',');
      parsed = std::string(trim(value.substr(0, end)));
      value.remove_prefix(end == std::string_view::npos ? value.size() : end);
    }
    if (key == "realm") challenge.realm = parsed;
    if (key == "nonce") {
      challenge.nonce = parsed;
      has_nonce = true;
    }
    if (key == "opaque") challenge.opaque = parsed;
    if (key == "algorithm") challenge.algorithm = parsed;
    if (key == "qop") {
      // A comma-separated list inside the quotes, e.g. "auth,auth-int".
      std::string_view options = parsed;
      while (!options.empty()) {
        const size_t comma = options.find(',');
        if (iequals(trim(options.substr(0, comma)), "auth")) challenge.qop_auth = true;
        options.remove_prefix(comma == std::string_view::npos ? options.size() : comma + 1);
      }
    }
  }
  if (!has_nonce) return std::nullopt;
  return challenge;
}

std::string digest_response(const Credentials& credentials, const Challenge& challenge, std::string_view method,
                            std::string_view uri, std::string_view nc, std::string_view cnonce) {
  const std::string ha1 = md5_hex(join({credentials.username, challenge.realm, credentials.password}));
  const std::string ha2 = md5_hex(join({method, uri}));
  if (challenge.qop_auth) return md5_hex(join({ha1, challenge.nonce, nc, cnonce, "auth", ha2}));
  return md5_hex(join({ha1, challenge.nonce, ha2}));
}

std::optional<std::string> authorization_value(const Credentials& credentials, const Challenge& challenge,
                                               std::string_view method, std::string_view uri) {
  if (!challenge.algorithm.empty() && !iequals(challenge.algorithm, "MD5")) return std::nullopt;
  // Every challenge gets a fresh request, so the nonce count is always 1.
  const std::string nc = "00000001";
  const std::string cnonce = challenge.qop_auth ? random_hex(8) : std::string{};
  std::string value = "Digest username=\"" + credentials.username + "\", realm=\"" + challenge.realm +
                      "\", nonce=\"" + challenge.nonce + "\", uri=\"" + std::string(uri) + "\", response=\"" +
                      digest_response(credentials, challenge, method, uri, nc, cnonce) + "\", algorithm=MD5";
  if (challenge.qop_auth) value += ", qop=auth, nc=" + nc + ", cnonce=\"" + cnonce + "\"";
  if (!challenge.opaque.empty()) value += ", opaque=\"" + challenge.opaque + "\"";
  return value;
}

}  // namespace ketphone::sip
