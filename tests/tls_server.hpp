#pragma once

// The server side of the TLS tests, played with OpenSSL whichever implementation the client uses.

#include <chrono>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "sip/stream_framer.hpp"

namespace ketphone::test {

// A certificate authority and one server certificate made at run time, so no private key is kept
// in the repository. The server certificate meets Apple's rules for TLS server certificates.
class TestPki {
 public:
  // `names` go into the server certificate's subjectAltName: DNS names or IP addresses.
  explicit TestPki(const std::vector<std::string>& names);
  ~TestPki();
  TestPki(const TestPki&) = delete;
  TestPki& operator=(const TestPki&) = delete;

  // The authority's certificate, the trust anchor a client is given.
  const std::string& ca_pem() const;

 private:
  friend class TlsServer;
  struct State;
  std::unique_ptr<State> state_;
};

// One accepted connection with its handshake done. Blocking, for the test thread.
class TlsSession {
 public:
  ~TlsSession();
  TlsSession(const TlsSession&) = delete;
  TlsSession& operator=(const TlsSession&) = delete;

  void send(std::string_view bytes);
  // The next SIP message, framed by Content-Length. Nothing on timeout or when the client closed.
  std::optional<std::string> receive_message(std::chrono::milliseconds timeout = std::chrono::seconds(3));
  // Bytes as they come, CRLF keep-alives included. Nothing on timeout or when the client closed.
  std::optional<std::string> receive_raw(std::chrono::milliseconds timeout = std::chrono::seconds(3));

 private:
  friend class TlsServer;
  TlsSession(void* ssl, int fd) : ssl_(ssl), fd_(fd) {}
  void* ssl_;
  int fd_;
  sip::StreamFramer framer_;
};

// Listens on 127.0.0.1 on a port of the system's choosing.
class TlsServer {
 public:
  explicit TlsServer(const TestPki& pki);
  ~TlsServer();
  TlsServer(const TlsServer&) = delete;
  TlsServer& operator=(const TlsServer&) = delete;

  uint16_t port() const { return port_; }
  // Takes the next connection and completes its handshake. Nothing on timeout or when the
  // handshake fails, which is what a client that refuses the certificate causes.
  std::unique_ptr<TlsSession> accept(std::chrono::milliseconds timeout = std::chrono::seconds(3));

 private:
  void* context_;
  int fd_ = -1;
  uint16_t port_ = 0;
};

}  // namespace ketphone::test
