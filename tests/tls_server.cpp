#include "tls_server.hpp"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <stdexcept>

namespace ketphone::test {
namespace {

void require(bool ok, const char* what) {
  if (!ok) throw std::runtime_error(std::string("test PKI: ") + what);
}

EVP_PKEY* make_key() {
  EVP_PKEY_CTX* context = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, nullptr);
  EVP_PKEY* key = nullptr;
  const bool ok = context != nullptr && EVP_PKEY_keygen_init(context) == 1 &&
                  EVP_PKEY_CTX_set_ec_paramgen_curve_nid(context, NID_X9_62_prime256v1) == 1 &&
                  EVP_PKEY_keygen(context, &key) == 1;
  EVP_PKEY_CTX_free(context);
  require(ok, "key");
  return key;
}

void add_extension(X509* certificate, X509V3_CTX* context, int nid, const std::string& value) {
  X509_EXTENSION* extension = X509V3_EXT_conf_nid(nullptr, context, nid, value.c_str());
  require(extension != nullptr && X509_add_ext(certificate, extension, -1) == 1, "extension");
  X509_EXTENSION_free(extension);
}

// A CA when `issuer` is null (self-signed), otherwise a server certificate for `names`. One day of
// validity, an extended key usage of serverAuth and the names in subjectAltName are what Apple's
// trust evaluation insists on.
X509* make_certificate(EVP_PKEY* key, const char* common_name, X509* issuer, EVP_PKEY* issuer_key,
                       const std::vector<std::string>& names) {
  static long serial = 1;
  X509* certificate = X509_new();
  require(certificate != nullptr, "certificate");
  X509_set_version(certificate, 2);
  ASN1_INTEGER_set(X509_get_serialNumber(certificate), serial++);
  X509_gmtime_adj(X509_getm_notBefore(certificate), -3600);
  X509_gmtime_adj(X509_getm_notAfter(certificate), 86400);
  X509_set_pubkey(certificate, key);
  X509_NAME* name = X509_get_subject_name(certificate);
  X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, reinterpret_cast<const unsigned char*>(common_name), -1, -1, 0);
  X509_set_issuer_name(certificate, issuer != nullptr ? X509_get_subject_name(issuer) : name);

  X509V3_CTX context;
  X509V3_set_ctx_nodb(&context);
  X509V3_set_ctx(&context, issuer != nullptr ? issuer : certificate, certificate, nullptr, nullptr, 0);
  add_extension(certificate, &context, NID_subject_key_identifier, "hash");
  if (issuer == nullptr) {
    add_extension(certificate, &context, NID_basic_constraints, "critical,CA:TRUE");
    add_extension(certificate, &context, NID_key_usage, "critical,keyCertSign,cRLSign");
  } else {
    std::string alt;
    for (const auto& entry : names) {
      unsigned char scratch[16];
      const bool address = inet_pton(AF_INET, entry.c_str(), scratch) == 1 || inet_pton(AF_INET6, entry.c_str(), scratch) == 1;
      alt += (alt.empty() ? "" : ",") + std::string(address ? "IP:" : "DNS:") + entry;
    }
    add_extension(certificate, &context, NID_authority_key_identifier, "keyid:always");
    add_extension(certificate, &context, NID_basic_constraints, "critical,CA:FALSE");
    add_extension(certificate, &context, NID_key_usage, "critical,digitalSignature");
    add_extension(certificate, &context, NID_ext_key_usage, "serverAuth");
    add_extension(certificate, &context, NID_subject_alt_name, alt);
  }
  require(X509_sign(certificate, issuer_key != nullptr ? issuer_key : key, EVP_sha256()) > 0, "sign");
  return certificate;
}

std::string pem_of(X509* certificate) {
  BIO* bio = BIO_new(BIO_s_mem());
  PEM_write_bio_X509(bio, certificate);
  char* data = nullptr;
  const long size = BIO_get_mem_data(bio, &data);
  std::string out(data, static_cast<size_t>(size));
  BIO_free(bio);
  return out;
}

SSL* ssl_of(void* handle) { return static_cast<SSL*>(handle); }

}  // namespace

struct TestPki::State {
  EVP_PKEY* ca_key = nullptr;
  X509* ca = nullptr;
  EVP_PKEY* server_key = nullptr;
  X509* server = nullptr;
  std::string ca_pem;
};

TestPki::TestPki(const std::vector<std::string>& names) : state_(std::make_unique<State>()) {
  state_->ca_key = make_key();
  state_->ca = make_certificate(state_->ca_key, "KetPhone Test CA", nullptr, nullptr, {});
  state_->server_key = make_key();
  state_->server = make_certificate(state_->server_key, names.front().c_str(), state_->ca, state_->ca_key, names);
  state_->ca_pem = pem_of(state_->ca);
}

TestPki::~TestPki() {
  X509_free(state_->server);
  EVP_PKEY_free(state_->server_key);
  X509_free(state_->ca);
  EVP_PKEY_free(state_->ca_key);
}

const std::string& TestPki::ca_pem() const { return state_->ca_pem; }

TlsServer::TlsServer(const TestPki& pki, bool tls12_only) {
  SSL_CTX* context = SSL_CTX_new(TLS_server_method());
  require(context != nullptr, "server context");
  SSL_CTX_set_min_proto_version(context, TLS1_2_VERSION);
  if (tls12_only) SSL_CTX_set_max_proto_version(context, TLS1_2_VERSION);
  require(SSL_CTX_use_certificate(context, pki.state_->server) == 1 &&
              SSL_CTX_use_PrivateKey(context, pki.state_->server_key) == 1,
          "server certificate");
  context_ = context;
  fd_ = ::socket(AF_INET, SOCK_STREAM, 0);
  sockaddr_in address{};
  address.sin_family = AF_INET;
  address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  require(::bind(fd_, reinterpret_cast<sockaddr*>(&address), sizeof(address)) == 0 && ::listen(fd_, 4) == 0, "listen");
  socklen_t length = sizeof(address);
  ::getsockname(fd_, reinterpret_cast<sockaddr*>(&address), &length);
  port_ = ntohs(address.sin_port);
}

TlsServer::~TlsServer() {
  ::close(fd_);
  SSL_CTX_free(static_cast<SSL_CTX*>(context_));
}

std::unique_ptr<TlsSession> TlsServer::accept(std::chrono::milliseconds timeout) {
  pollfd listening{fd_, POLLIN, 0};
  if (::poll(&listening, 1, static_cast<int>(timeout.count())) != 1) return nullptr;
  const int fd = ::accept(fd_, nullptr, nullptr);
  if (fd < 0) return nullptr;
  // Blocking, with a bound on every read and write so a stuck client fails the test, not hangs it.
  timeval bound{3, 0};
  ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &bound, sizeof(bound));
  ::setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &bound, sizeof(bound));
#ifdef SO_NOSIGPIPE
  const int one = 1;
  ::setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one));
#endif
  SSL* ssl = SSL_new(static_cast<SSL_CTX*>(context_));
  if (ssl == nullptr || SSL_set_fd(ssl, fd) != 1 || SSL_accept(ssl) != 1) {
    ERR_clear_error();
    SSL_free(ssl);
    ::close(fd);
    return nullptr;
  }
  return std::unique_ptr<TlsSession>(new TlsSession(ssl, fd));
}

TlsSession::~TlsSession() {
  SSL_shutdown(ssl_of(ssl_));
  SSL_free(ssl_of(ssl_));
  ::close(fd_);
}

void TlsSession::send(std::string_view bytes) {
  while (!bytes.empty()) {
    const int written = SSL_write(ssl_of(ssl_), bytes.data(), static_cast<int>(bytes.size()));
    if (written <= 0) throw std::runtime_error("TLS test server: write failed");
    bytes.remove_prefix(static_cast<size_t>(written));
  }
}

std::optional<std::string> TlsSession::receive_raw(std::chrono::milliseconds timeout) {
  if (SSL_pending(ssl_of(ssl_)) == 0) {
    pollfd readable{fd_, POLLIN, 0};
    if (::poll(&readable, 1, static_cast<int>(timeout.count())) != 1) return std::nullopt;
  }
  char buffer[16384];
  const int size = SSL_read(ssl_of(ssl_), buffer, sizeof(buffer));
  if (size <= 0) {
    ERR_clear_error();
    return std::nullopt;
  }
  return std::string(buffer, static_cast<size_t>(size));
}

std::optional<std::string> TlsSession::receive_message(std::chrono::milliseconds timeout) {
  const auto deadline = std::chrono::steady_clock::now() + timeout;
  for (;;) {
    if (auto message = framer_.next()) return message;
    const auto left = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - std::chrono::steady_clock::now());
    if (left.count() <= 0) return std::nullopt;
    const auto bytes = receive_raw(left);
    if (!bytes) return std::nullopt;
    framer_.push(*bytes);
  }
}

}  // namespace ketphone::test
