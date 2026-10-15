#include <string>

#include "net/tls_transport.hpp"
#include "sip/base64.hpp"

namespace ketphone::net {

std::optional<std::vector<std::vector<uint8_t>>> pem_certificates(std::string_view pem) {
  static constexpr std::string_view kBegin = "-----BEGIN CERTIFICATE-----";
  static constexpr std::string_view kEnd = "-----END CERTIFICATE-----";
  std::vector<std::vector<uint8_t>> out;
  for (;;) {
    const size_t begin = pem.find(kBegin);
    if (begin == std::string_view::npos) break;
    pem.remove_prefix(begin + kBegin.size());
    const size_t end = pem.find(kEnd);
    if (end == std::string_view::npos) return std::nullopt;
    std::string body;
    for (const char c : pem.substr(0, end)) {
      if (c != '\r' && c != '\n' && c != ' ' && c != '\t') body.push_back(c);
    }
    auto der = sip::base64_decode(body);
    if (!der || der->empty()) return std::nullopt;
    out.push_back(std::move(*der));
    pem.remove_prefix(end + kEnd.size());
  }
  if (out.empty()) return std::nullopt;
  return out;
}

#if !defined(KETPHONE_TLS_APPLE) && !defined(KETPHONE_TLS_OPENSSL)
bool tls_supported() { return false; }
std::unique_ptr<TlsConnection> connect_tls(const TlsOptions&, StreamListener&) { return nullptr; }
#endif

}  // namespace ketphone::net
