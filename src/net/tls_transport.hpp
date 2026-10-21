#pragma once

#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace ketphone::net {

struct TlsOptions {
  // Host name or address to connect to.
  std::string host;
  uint16_t port = 5061;
  // Name the server certificate must be issued for, also sent as SNI; empty means `host`.
  std::string server_name;
  // PEM certificates the server's chain must end in, and then the only ones trusted. Empty uses the
  // system's trust store.
  std::string trust_anchors_pem;
};

enum class StreamError {
  // The connection was up and ended (the server closed it, or the network went away).
  Closed,
  // No connection could be made: nothing listening, no route, timeout.
  ConnectFailed,
  // The TLS handshake failed, normally because the certificate is not trusted or not for this name.
  HandshakeFailed,
};

// Callbacks of one connection. They come from the connection's own thread or dispatch queue, one at
// a time, never after the connection is destroyed, and must not call back into the connection.
class StreamListener {
 public:
  virtual ~StreamListener() = default;
  virtual void on_connected() = 0;
  virtual void on_data(std::span<const uint8_t> data) = 0;
  // The connection failed or ended; nothing follows.
  virtual void on_closed(StreamError error) = 0;
};

// A TLS 1.2+ client connection. It starts connecting when created and closes when destroyed.
class TlsConnection {
 public:
  virtual ~TlsConnection() = default;
  // Queues bytes; they go out in order once the handshake is done. After the connection ended they
  // are dropped.
  virtual void send(std::string bytes) = 0;
};

// Whether this build has a TLS implementation (Network.framework on Apple platforms, OpenSSL
// elsewhere).
bool tls_supported();

// Starts connecting. Nothing when TLS is not built in or the trust anchors do not parse.
std::unique_ptr<TlsConnection> connect_tls(const TlsOptions& options, StreamListener& listener);

// The DER certificates in PEM text, in order. Nothing when there is none or one does not decode.
std::optional<std::vector<std::vector<uint8_t>>> pem_certificates(std::string_view pem);

}  // namespace ketphone::net
