// TLS through OpenSSL, for Linux (the command-line tool, tests in containers) and other platforms
// without Network.framework. Each connection runs its own I/O thread over a non-blocking socket.
#include "net/tls_transport.hpp"

#if defined(KETPHONE_TLS_OPENSSL)

#include <arpa/inet.h>
#include <fcntl.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <sys/socket.h>
#include <unistd.h>

#include <array>
#include <atomic>
#include <chrono>
#include <mutex>
#include <thread>

#include "net/udp_socket.hpp"

namespace ketphone::net {
namespace {

using namespace std::chrono_literals;

constexpr auto kConnectTimeout = 10s;

class OpenSslTls final : public TlsConnection {
 public:
  static std::unique_ptr<OpenSslTls> create(const TlsOptions& options, StreamListener& listener) {
    SSL_CTX* context = SSL_CTX_new(TLS_client_method());
    if (context == nullptr) return nullptr;
    SSL_CTX_set_min_proto_version(context, TLS1_2_VERSION);
    SSL_CTX_set_verify(context, SSL_VERIFY_PEER, nullptr);
    SSL_CTX_set_mode(context, SSL_MODE_ENABLE_PARTIAL_WRITE | SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);
    bool trusted = true;
    if (options.trust_anchors_pem.empty()) {
      trusted = SSL_CTX_set_default_verify_paths(context) == 1;
    } else {
      const auto certificates = pem_certificates(options.trust_anchors_pem);
      X509_STORE* store = SSL_CTX_get_cert_store(context);
      trusted = certificates.has_value();
      for (const auto& der : certificates.value_or(std::vector<std::vector<uint8_t>>{})) {
        const unsigned char* cursor = der.data();
        X509* certificate = d2i_X509(nullptr, &cursor, static_cast<long>(der.size()));
        trusted = trusted && certificate != nullptr && X509_STORE_add_cert(store, certificate) == 1;
        X509_free(certificate);
      }
    }
    if (!trusted) {
      SSL_CTX_free(context);
      return nullptr;
    }
    auto connection = std::unique_ptr<OpenSslTls>(new OpenSslTls(options, listener, context));
    if (!connection->start()) return nullptr;
    return connection;
  }

  ~OpenSslTls() override {
    stopping_ = true;
    wake();
    if (thread_.joinable()) thread_.join();
    for (const int fd : wake_) {
      if (fd >= 0) ::close(fd);
    }
    SSL_CTX_free(context_);
  }

  OpenSslTls(const OpenSslTls&) = delete;
  OpenSslTls& operator=(const OpenSslTls&) = delete;

  void send(std::string bytes) override {
    {
      std::lock_guard lock(outbox_mutex_);
      outbox_ += bytes;
    }
    wake();
  }

 private:
  OpenSslTls(const TlsOptions& options, StreamListener& listener, SSL_CTX* context)
      : options_(options), listener_(listener), context_(context) {}

  bool start() {
    if (::pipe(wake_) != 0) return false;
    for (const int fd : wake_) {
      fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK);
      fcntl(fd, F_SETFD, FD_CLOEXEC);
    }
    thread_ = std::thread([this] { run(); });
    return true;
  }

  void wake() {
    const uint8_t byte = 1;
    [[maybe_unused]] const auto written = ::write(wake_[1], &byte, 1);
  }

  void drain_wake() {
    std::array<uint8_t, 64> scratch{};
    while (::read(wake_[0], scratch.data(), scratch.size()) > 0) {
    }
  }

  // Waits for `events` on the socket or a wake-up; false when stopping or out of time.
  bool wait(int fd, short events, std::chrono::steady_clock::time_point deadline) {
    for (;;) {
      if (stopping_) return false;
      const auto left = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - std::chrono::steady_clock::now());
      if (left.count() <= 0) return false;
      std::array<pollfd, 2> fds{{{fd, events, 0}, {wake_[0], POLLIN, 0}}};
      ::poll(fds.data(), fds.size(), static_cast<int>(left.count()));
      drain_wake();
      if (stopping_) return false;
      if (fds[0].revents != 0) return true;
    }
  }

  int connect_socket(std::chrono::steady_clock::time_point deadline) {
    for (const auto& endpoint : resolve_all(options_.host, options_.port)) {
      const int fd = ::socket(endpoint.family, SOCK_STREAM, 0);
      if (fd < 0) continue;
      fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK);
      fcntl(fd, F_SETFD, FD_CLOEXEC);
#ifdef SO_NOSIGPIPE
      const int one = 1;
      ::setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one));
#endif
      const sockaddr_storage address = endpoint.to_sockaddr();
      int result = ::connect(fd, reinterpret_cast<const sockaddr*>(&address), endpoint.sockaddr_length());
      if (result != 0 && errno == EINPROGRESS && wait(fd, POLLOUT, deadline)) {
        int error = 0;
        socklen_t length = sizeof(error);
        result = ::getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &length) == 0 && error == 0 ? 0 : -1;
      }
      if (result == 0) return fd;
      ::close(fd);
      if (stopping_) break;
    }
    return -1;
  }

  // The name in the certificate must match: a DNS name, or an IP address in an iPAddress entry.
  bool expect_name(SSL* ssl, const std::string& name) {
    std::array<uint8_t, 16> scratch{};
    const bool address =
        ::inet_pton(AF_INET, name.c_str(), scratch.data()) == 1 || ::inet_pton(AF_INET6, name.c_str(), scratch.data()) == 1;
    if (address) return X509_VERIFY_PARAM_set1_ip_asc(SSL_get0_param(ssl), name.c_str()) == 1;
    // SSL_set_tlsext_host_name, without the C cast in that macro which GCC reports even from a
    // system header.
    const long sni = SSL_ctrl(ssl, SSL_CTRL_SET_TLSEXT_HOSTNAME, TLSEXT_NAMETYPE_host_name, const_cast<char*>(name.c_str()));
    return sni == 1 && SSL_set1_host(ssl, name.c_str()) == 1;
  }

  void run() {
    // A write to a socket the peer has closed raises SIGPIPE on Linux, which would kill the app. It
    // stays pending on this thread instead, and the write fails with EPIPE.
    sigset_t pipe_signal;
    sigemptyset(&pipe_signal);
    sigaddset(&pipe_signal, SIGPIPE);
    pthread_sigmask(SIG_BLOCK, &pipe_signal, nullptr);

    const auto deadline = std::chrono::steady_clock::now() + kConnectTimeout;
    const int fd = connect_socket(deadline);
    if (fd < 0) {
      if (!stopping_) listener_.on_closed(StreamError::ConnectFailed);
      return;
    }
    SSL* ssl = SSL_new(context_);
    const std::string& name = options_.server_name.empty() ? options_.host : options_.server_name;
    const Handshake outcome = ssl != nullptr && expect_name(ssl, name) && SSL_set_fd(ssl, fd) == 1
                                  ? handshake(ssl, fd, deadline)
                                  : Handshake::Refused;
    if (outcome != Handshake::Done) {
      if (ssl != nullptr) SSL_free(ssl);
      ::close(fd);
      if (!stopping_) {
        listener_.on_closed(outcome == Handshake::TimedOut ? StreamError::ConnectFailed : StreamError::HandshakeFailed);
      }
      return;
    }
    listener_.on_connected();
    const StreamError error = pump(ssl, fd);
    SSL_shutdown(ssl);
    SSL_free(ssl);
    ::close(fd);
    if (!stopping_) listener_.on_closed(error);
  }

  enum class Handshake { Done, TimedOut, Refused };

  // Refused covers an untrusted certificate, a wrong name and a TLS alert from the server.
  Handshake handshake(SSL* ssl, int fd, std::chrono::steady_clock::time_point deadline) {
    for (;;) {
      const int result = SSL_connect(ssl);
      if (result == 1) return Handshake::Done;
      const int reason = SSL_get_error(ssl, result);
      if (reason == SSL_ERROR_WANT_READ) {
        if (!wait(fd, POLLIN, deadline)) return Handshake::TimedOut;
      } else if (reason == SSL_ERROR_WANT_WRITE) {
        if (!wait(fd, POLLOUT, deadline)) return Handshake::TimedOut;
      } else {
        ERR_clear_error();
        return Handshake::Refused;
      }
    }
  }

  // Moves bytes both ways until the connection ends or the object is destroyed. Each round works
  // before it waits: what was queued during the handshake has had its wake-up consumed there, and
  // a TLS 1.2 server sends nothing that would wake the wait first.
  StreamError pump(SSL* ssl, int fd) {
    std::array<uint8_t, 16384> buffer{};
    std::string pending;
    bool want_write = false;
    for (;;) {
      // Read everything that is there, including what OpenSSL already buffered.
      for (;;) {
        const int size = SSL_read(ssl, buffer.data(), static_cast<int>(buffer.size()));
        if (size > 0) {
          listener_.on_data({buffer.data(), static_cast<size_t>(size)});
          continue;
        }
        const int reason = SSL_get_error(ssl, size);
        if (reason == SSL_ERROR_WANT_READ || reason == SSL_ERROR_WANT_WRITE) break;
        ERR_clear_error();
        return StreamError::Closed;  // closed by the peer, or a TLS error
      }

      {
        std::lock_guard lock(outbox_mutex_);
        pending += outbox_;
        outbox_.clear();
      }
      want_write = false;
      while (!pending.empty()) {
        const int size = SSL_write(ssl, pending.data(), static_cast<int>(std::min<size_t>(pending.size(), 1 << 20)));
        if (size > 0) {
          pending.erase(0, static_cast<size_t>(size));
          continue;
        }
        const int reason = SSL_get_error(ssl, size);
        if (reason == SSL_ERROR_WANT_WRITE || reason == SSL_ERROR_WANT_READ) {
          want_write = true;
          break;
        }
        ERR_clear_error();
        return StreamError::Closed;
      }

      // A send after the outbox was taken above has left a byte in the wake pipe, so this returns.
      std::array<pollfd, 2> fds{{{fd, static_cast<short>(POLLIN | (want_write ? POLLOUT : 0)), 0}, {wake_[0], POLLIN, 0}}};
      ::poll(fds.data(), fds.size(), -1);
      drain_wake();
      if (stopping_) return StreamError::Closed;
    }
  }

  TlsOptions options_;
  StreamListener& listener_;
  SSL_CTX* context_;
  std::thread thread_;
  int wake_[2] = {-1, -1};
  std::atomic<bool> stopping_{false};
  std::mutex outbox_mutex_;
  std::string outbox_;
};

}  // namespace

bool tls_supported() { return true; }

std::unique_ptr<TlsConnection> connect_tls(const TlsOptions& options, StreamListener& listener) {
  if (options.host.empty() || options.port == 0) return nullptr;
  return OpenSslTls::create(options, listener);
}

}  // namespace ketphone::net

#endif  // KETPHONE_TLS_OPENSSL
