// TLS on Apple platforms through Network.framework's C API, so the system does the handshake, the
// certificate checks and TLS 1.3, and no TLS library ships inside the app.
#include "net/tls_transport.hpp"

#if defined(KETPHONE_TLS_APPLE)

#include <CoreFoundation/CoreFoundation.h>
#include <Network/Network.h>
#include <Security/Security.h>
#include <dispatch/dispatch.h>

#include <mutex>

namespace ketphone::net {
namespace {

// Trust anchors and the name to check, kept alive by every block that may evaluate a certificate.
struct Trust {
  CFArrayRef anchors = nullptr;  // null: the system trust store
  CFStringRef name = nullptr;
  Trust() = default;
  Trust(const Trust&) = delete;
  Trust& operator=(const Trust&) = delete;
  ~Trust() {
    if (anchors != nullptr) CFRelease(anchors);
    if (name != nullptr) CFRelease(name);
  }
};

// What the connection's blocks share with the connection object. The blocks can run briefly after
// the object is gone, so they hold this instead of the object.
struct Shared {
  std::mutex mutex;
  StreamListener* listener = nullptr;  // null once closed or detached
  bool connected = false;

  void notify_connected() {
    std::lock_guard lock(mutex);
    if (listener == nullptr) return;
    connected = true;
    listener->on_connected();
  }

  void notify_data(const void* bytes, size_t size) {
    std::lock_guard lock(mutex);
    if (listener != nullptr) listener->on_data({static_cast<const uint8_t*>(bytes), size});
  }

  // Reports the end once; holding the mutex makes the destructor wait for a callback in progress.
  void close(nw_error_t error) {
    std::lock_guard lock(mutex);
    if (listener == nullptr) return;
    StreamListener* closing = listener;
    listener = nullptr;
    StreamError reason = connected ? StreamError::Closed : StreamError::ConnectFailed;
    if (error != nullptr && nw_error_get_error_domain(error) == nw_error_domain_tls) reason = StreamError::HandshakeFailed;
    closing->on_closed(reason);
  }
};

bool evaluate(sec_trust_t trust_ref, const Trust& trust) {
  SecTrustRef evaluation = sec_trust_copy_ref(trust_ref);
  if (evaluation == nullptr) return false;
  SecPolicyRef policy = SecPolicyCreateSSL(true, trust.name);
  const bool ok = policy != nullptr && SecTrustSetPolicies(evaluation, policy) == errSecSuccess &&
                  SecTrustSetAnchorCertificates(evaluation, trust.anchors) == errSecSuccess &&
                  SecTrustSetAnchorCertificatesOnly(evaluation, true) == errSecSuccess &&
                  SecTrustEvaluateWithError(evaluation, nullptr);
  if (policy != nullptr) CFRelease(policy);
  CFRelease(evaluation);
  return ok;
}

// Keeps one receive outstanding until the connection ends. Each pending receive holds a reference to
// the connection, so the chain needs nothing from the connection object.
void receive(nw_connection_t connection, std::shared_ptr<Shared> shared) {
  nw_retain(connection);
  nw_connection_receive(connection, 1, 65536,
                        ^(dispatch_data_t content, nw_content_context_t, bool is_complete, nw_error_t error) {
                          if (content != nullptr) {
                            dispatch_data_apply(content, ^bool(dispatch_data_t, size_t, const void* buffer, size_t size) {
                              shared->notify_data(buffer, size);
                              return true;
                            });
                          }
                          if (error != nullptr || is_complete) {
                            shared->close(error);
                            nw_connection_cancel(connection);
                          } else {
                            receive(connection, shared);
                          }
                          nw_release(connection);
                        });
}

std::shared_ptr<Trust> trust_for(const TlsOptions& options) {
  auto trust = std::make_shared<Trust>();
  const std::string& name = options.server_name.empty() ? options.host : options.server_name;
  trust->name = CFStringCreateWithCString(kCFAllocatorDefault, name.c_str(), kCFStringEncodingUTF8);
  if (trust->name == nullptr) return nullptr;
  if (options.trust_anchors_pem.empty()) return trust;
  const auto certificates = pem_certificates(options.trust_anchors_pem);
  if (!certificates) return nullptr;
  CFMutableArrayRef anchors = CFArrayCreateMutable(kCFAllocatorDefault, 0, &kCFTypeArrayCallBacks);
  trust->anchors = anchors;
  for (const auto& der : *certificates) {
    CFDataRef data = CFDataCreate(kCFAllocatorDefault, der.data(), static_cast<CFIndex>(der.size()));
    if (data == nullptr) return nullptr;
    SecCertificateRef certificate = SecCertificateCreateWithData(kCFAllocatorDefault, data);
    CFRelease(data);
    if (certificate == nullptr) return nullptr;
    CFArrayAppendValue(anchors, certificate);
    CFRelease(certificate);
  }
  return trust;
}

class AppleTls final : public TlsConnection {
 public:
  static std::unique_ptr<AppleTls> create(const TlsOptions& options, StreamListener& listener) {
    const auto trust = trust_for(options);
    if (!trust) return nullptr;
    const std::string name = options.server_name.empty() ? options.host : options.server_name;
    const std::string port = std::to_string(options.port);
    nw_endpoint_t endpoint = nw_endpoint_create_host(options.host.c_str(), port.c_str());
    if (endpoint == nullptr) return nullptr;

    dispatch_queue_t queue = dispatch_queue_create("vn.ketviet.ketphone.tls", DISPATCH_QUEUE_SERIAL);
    nw_parameters_t parameters = nw_parameters_create_secure_tcp(
        ^(nw_protocol_options_t tls) {
          sec_protocol_options_t security = nw_tls_copy_sec_protocol_options(tls);
          sec_protocol_options_set_min_tls_protocol_version(security, tls_protocol_version_TLSv12);
          sec_protocol_options_set_tls_server_name(security, name.c_str());
          if (trust->anchors != nullptr) {
            sec_protocol_options_set_verify_block(
                security,
                ^(sec_protocol_metadata_t, sec_trust_t trust_ref, sec_protocol_verify_complete_t complete) {
                  complete(evaluate(trust_ref, *trust));
                },
                queue);
          }
          sec_release(security);
        },
        ^(nw_protocol_options_t tcp) {
          nw_tcp_options_set_no_delay(tcp, true);
          nw_tcp_options_set_connection_timeout(tcp, 10);
        });
    nw_connection_t connection = nw_connection_create(endpoint, parameters);
    nw_release(parameters);
    nw_release(endpoint);
    if (connection == nullptr) {
      dispatch_release(queue);
      return nullptr;
    }

    auto shared = std::make_shared<Shared>();
    shared->listener = &listener;
    nw_connection_set_queue(connection, queue);
    // The handler belongs to the connection, so the connection is alive whenever it runs.
    nw_connection_set_state_changed_handler(connection, ^(nw_connection_state_t state, nw_error_t error) {
      switch (state) {
        case nw_connection_state_ready:
          shared->notify_connected();
          receive(connection, shared);
          break;
        case nw_connection_state_waiting:
          // Refused or no route: Network.framework would keep trying by itself, but retries and their
          // backoff belong to the engine.
        case nw_connection_state_failed:
          shared->close(error);
          nw_connection_cancel(connection);
          break;
        default:
          break;
      }
    });
    nw_connection_start(connection);
    return std::unique_ptr<AppleTls>(new AppleTls(connection, queue, std::move(shared)));
  }

  ~AppleTls() override {
    {
      std::lock_guard lock(shared_->mutex);
      shared_->listener = nullptr;
    }
    nw_connection_cancel(connection_);
    nw_release(connection_);
    dispatch_release(queue_);
  }

  AppleTls(const AppleTls&) = delete;
  AppleTls& operator=(const AppleTls&) = delete;

  void send(std::string bytes) override {
    if (bytes.empty()) return;
    auto* owned = new std::string(std::move(bytes));
    dispatch_data_t data = dispatch_data_create(owned->data(), owned->size(), queue_, ^{
      delete owned;
    });
    // Network.framework queues sends made before the handshake finishes. A failure surfaces in the
    // state handler, so the completion has nothing to do.
    nw_connection_send(connection_, data, NW_CONNECTION_DEFAULT_STREAM_CONTEXT, false, ^(nw_error_t) {
    });
    dispatch_release(data);
  }

 private:
  AppleTls(nw_connection_t connection, dispatch_queue_t queue, std::shared_ptr<Shared> shared)
      : connection_(connection), queue_(queue), shared_(std::move(shared)) {}

  nw_connection_t connection_;
  dispatch_queue_t queue_;
  std::shared_ptr<Shared> shared_;
};

}  // namespace

bool tls_supported() { return true; }

std::unique_ptr<TlsConnection> connect_tls(const TlsOptions& options, StreamListener& listener) {
  if (options.host.empty() || options.port == 0) return nullptr;
  return AppleTls::create(options, listener);
}

}  // namespace ketphone::net

#endif  // KETPHONE_TLS_APPLE
