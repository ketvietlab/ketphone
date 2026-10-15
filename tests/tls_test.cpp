// SIP over TLS with SRTP media, against an OpenSSL server in the test: the transport on its own,
// then the C API end to end. The client is whichever TLS implementation this build uses.
#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstring>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <type_traits>
#include <vector>

#include "check.hpp"
#include "ketphone/ketphone.h"
#include "media/rtp.hpp"
#include "media/srtp.hpp"
#include "net/tls_transport.hpp"
#include "net/udp_socket.hpp"
#include "sip/message.hpp"
#include "sip/sdp.hpp"

#if defined(KETPHONE_TEST_TLS)
#include "tls_server.hpp"
#endif

using namespace ketphone;
using namespace std::chrono_literals;

TEST(pem_certificates_reads_every_certificate_in_order) {
  const std::string pem =
      "junk before\n-----BEGIN CERTIFICATE-----\nAAEC\nAw==\n-----END CERTIFICATE-----\n"
      "-----BEGIN CERTIFICATE-----\r\nBAUG\r\n-----END CERTIFICATE-----\n";
  const auto certificates = net::pem_certificates(pem);
  CHECK(certificates.has_value());
  CHECK_EQ(certificates->size(), size_t{2});
  CHECK((*certificates)[0] == std::vector<uint8_t>({0, 1, 2, 3}));
  CHECK((*certificates)[1] == std::vector<uint8_t>({4, 5, 6}));
  CHECK(!net::pem_certificates("").has_value());
  CHECK(!net::pem_certificates("-----BEGIN CERTIFICATE-----\nAAEC\n").has_value());
  CHECK(!net::pem_certificates("-----BEGIN CERTIFICATE-----\n!!\n-----END CERTIFICATE-----\n").has_value());
  CHECK(!net::pem_certificates("-----BEGIN CERTIFICATE-----\n-----END CERTIFICATE-----\n").has_value());
}

#if defined(KETPHONE_TEST_TLS)

namespace {

using test::TestPki;
using test::TlsServer;
using test::TlsSession;

template <class Predicate>
bool await(Predicate ready, std::chrono::milliseconds limit = 3s) {
  const auto deadline = std::chrono::steady_clock::now() + limit;
  while (std::chrono::steady_clock::now() < deadline) {
    if (ready()) return true;
    std::this_thread::sleep_for(5ms);
  }
  return ready();
}

class Listener final : public net::StreamListener {
 public:
  void on_connected() override { connected = true; }
  void on_data(std::span<const uint8_t> data) override {
    std::lock_guard lock(mutex);
    received.append(reinterpret_cast<const char*>(data.data()), data.size());
  }
  void on_closed(net::StreamError reason) override {
    error = static_cast<int>(reason);
    closed = true;
  }
  std::string text() {
    std::lock_guard lock(mutex);
    return received;
  }

  std::atomic<bool> connected{false};
  std::atomic<bool> closed{false};
  std::atomic<int> error{-1};
  std::mutex mutex;
  std::string received;
};

net::TlsOptions options_for(const TlsServer& server, const TestPki& anchors, const std::string& name = "localhost") {
  net::TlsOptions options;
  options.host = "127.0.0.1";
  options.port = server.port();
  options.server_name = name;
  options.trust_anchors_pem = anchors.ca_pem();
  return options;
}

// Accepts in the background so that the client's handshake has a server whatever the outcome.
std::unique_ptr<TlsSession> accept_while(TlsServer& server, Listener& listener) {
  std::unique_ptr<TlsSession> session;
  std::thread acceptor([&] { session = server.accept(); });
  await([&] { return listener.connected.load() || listener.closed.load(); });
  acceptor.join();
  return session;
}

}  // namespace

TEST(tls_connects_to_a_server_from_the_given_authority_and_carries_bytes_both_ways) {
  CHECK(net::tls_supported());
  TestPki pki({"localhost", "127.0.0.1"});
  TlsServer server(pki);
  Listener listener;
  auto connection = net::connect_tls(options_for(server, pki), listener);
  CHECK(connection != nullptr);
  connection->send("sent before the handshake\r\n");
  auto session = accept_while(server, listener);
  CHECK(session != nullptr);
  CHECK(await([&] { return listener.connected.load(); }));
  CHECK_EQ(*session->receive_raw(), std::string("sent before the handshake\r\n"));
  session->send("hello from the server");
  CHECK(await([&] { return listener.text() == "hello from the server"; }));
  CHECK(!listener.closed);

  session.reset();  // the server hangs up
  CHECK(await([&] { return listener.closed.load(); }));
  CHECK_EQ(listener.error.load(), static_cast<int>(net::StreamError::Closed));

  // An IP address as the name is checked against the certificate's IP entries.
  Listener by_address;
  auto direct = net::connect_tls(options_for(server, pki, "127.0.0.1"), by_address);
  auto direct_session = accept_while(server, by_address);
  CHECK(direct_session != nullptr);
  CHECK(by_address.connected);
}

TEST(tls_refuses_a_server_from_another_authority_or_for_another_name) {
  TestPki pki({"localhost"});
  TestPki stranger({"localhost"});
  TlsServer server(pki);
  for (const bool wrong_name : {false, true}) {
    Listener listener;
    auto connection = net::connect_tls(options_for(server, wrong_name ? pki : stranger, wrong_name ? "sip.example.test" : "localhost"), listener);
    CHECK(connection != nullptr);
    std::thread acceptor([&] { server.accept(); });
    CHECK(await([&] { return listener.closed.load(); }, 5s));
    acceptor.join();
    CHECK(!listener.connected);
    CHECK_EQ(listener.error.load(), static_cast<int>(net::StreamError::HandshakeFailed));
  }
}

TEST(tls_reports_nothing_listening_as_a_failed_connection) {
  uint16_t port = 0;
  {
    TestPki pki({"localhost"});
    TlsServer closed(pki);
    port = closed.port();
  }
  TestPki pki({"localhost"});
  Listener listener;
  net::TlsOptions options;
  options.host = "127.0.0.1";
  options.port = port;
  options.server_name = "localhost";
  options.trust_anchors_pem = pki.ca_pem();
  auto connection = net::connect_tls(options, listener);
  CHECK(connection != nullptr);
  CHECK(await([&] { return listener.closed.load(); }, 12s));
  CHECK_EQ(listener.error.load(), static_cast<int>(net::StreamError::ConnectFailed));
  // Destroying a connection that already ended, or one still connecting, is quiet and safe.
  connection.reset();
  Listener pending;
  auto abandoned = net::connect_tls(options, pending);
  abandoned.reset();
  CHECK(!pending.connected);
}

// The C API over TLS ------------------------------------------------------------------------------

namespace {

struct Events {
  std::mutex mutex;
  std::vector<int> registrations;
  std::atomic<int> answered{0};
  std::atomic<int> ended{0};
  static void record(const ketphone_event* event, void* context) {
    auto& self = *static_cast<Events*>(context);
    if (event->kind == KETPHONE_EVENT_REGISTRATION) {
      std::lock_guard lock(self.mutex);
      self.registrations.push_back(event->status_code);
    }
    if (event->kind == KETPHONE_EVENT_CALL_ANSWERED) ++self.answered;
    if (event->kind == KETPHONE_EVENT_CALL_ENDED) ++self.ended;
  }
  std::vector<int> seen() {
    std::lock_guard lock(mutex);
    return registrations;
  }
};

using Engine = std::unique_ptr<ketphone_engine, decltype(&ketphone_engine_destroy)>;

Engine tls_engine(const TlsServer& server, const TestPki& anchors, Events& events) {
  ketphone_config config{};
  config.struct_size = sizeof(config);
  config.server_host = "127.0.0.1";
  config.server_port = server.port();
  config.extension = "1001";
  config.password = "secret";
  config.transport = KETPHONE_TRANSPORT_TLS;
  config.tls_trust_anchors = anchors.ca_pem().c_str();
  config.tls_server_name = "localhost";
  return Engine(ketphone_engine_create(&config, Events::record, &events), ketphone_engine_destroy);
}

sip::Message next_request(TlsSession& session, const std::string& method) {
  const auto text = session.receive_message();
  CHECK(text.has_value());
  const auto message = sip::parse_message(*text);
  CHECK(message.has_value());
  CHECK_EQ(message->method, method);
  return *message;
}

std::string reply(const sip::Message& request, const std::string& body = {}) {
  std::string out = "SIP/2.0 200 OK\r\n";
  for (const auto via : request.header_all("via")) out += "Via: " + std::string(via) + "\r\n";
  std::string to(*request.header("to"));
  if (to.find(";tag=") == std::string::npos) to += ";tag=server";
  out += "From: " + std::string(*request.header("from")) + "\r\nTo: " + to + "\r\n";
  out += "Call-ID: " + std::string(*request.header("call-id")) + "\r\n";
  out += "CSeq: " + std::string(*request.header("cseq")) + "\r\n";
  if (const auto expires = request.header("expires")) out += "Expires: " + std::string(*expires) + "\r\n";
  out += "Contact: <sip:asterisk@127.0.0.1;transport=tls>\r\n";
  if (!body.empty()) out += "Content-Type: application/sdp\r\n";
  out += "Content-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;
  return out;
}

void register_over(TlsSession& session, Events& events, size_t registrations) {
  const auto request = next_request(session, "REGISTER");
  CHECK(request.header("via")->starts_with("SIP/2.0/TLS 127.0.0.1;branch=z9hG4bK"));
  CHECK_EQ(std::string(*request.header("contact")), std::string("<sip:1001@127.0.0.1;transport=tls>"));
  session.send(reply(request));
  CHECK(await([&] { return events.seen().size() == registrations; }));
  CHECK_EQ(events.seen().back(), 200);
}

struct Packet {
  alignas(4) std::array<uint8_t, 2048> bytes{};
  size_t size = 0;
  net::Endpoint from;
};

std::optional<Packet> receive_packet(net::UdpSocket& socket) {
  Packet packet;
  if (!await([&] {
        const auto size = socket.receive(packet.bytes, &packet.from);
        packet.size = size.value_or(0);
        return packet.size > 0;
      })) {
    return std::nullopt;
  }
  return packet;
}

bool playout_shows(ketphone_engine* engine, int16_t sample, std::chrono::milliseconds limit) {
  std::array<int16_t, 160> playout{};
  return await(
      [&] {
        ketphone_audio_playout(engine, playout.data(), playout.size());
        return std::find(playout.begin(), playout.end(), sample) != playout.end();
      },
      limit);
}

}  // namespace

TEST(tls_c_api_registers_calls_with_srtp_and_registers_again_after_a_lost_connection) {
  TestPki pki({"localhost"});
  TlsServer server(pki);
  Events events;
  auto engine = tls_engine(server, pki, events);
  CHECK(engine != nullptr);
  CHECK(ketphone_register(engine.get()) == KETPHONE_OK);
  auto session = server.accept();
  CHECK(session != nullptr);
  register_over(*session, events, 1);

  auto media = net::UdpSocket::open(AF_INET);
  CHECK(media.has_value());
  const uint16_t media_port = media->local()->port;
  ketphone_call_id id = 0;
  CHECK(ketphone_call(engine.get(), "1002", &id) == KETPHONE_OK);
  const auto invite = next_request(*session, "INVITE");
  const auto offer = sip::parse_audio(invite.body);
  CHECK(offer.has_value());
  CHECK(offer->savp);
  CHECK_EQ(offer->crypto.size(), size_t{1});
  CHECK_EQ(offer->crypto[0].tag, uint32_t{1});
  const auto server_key = media::generate_srtp_key();
  CHECK(server_key.has_value());
  session->send(reply(invite, sip::build_audio_sdp("127.0.0.1", media_port, 1, 1, sip::LocalCrypto{true, 1, *server_key})));
  next_request(*session, "ACK");
  CHECK(await([&] { return events.answered.load() == 1; }));

  // What the engine sends authenticates under the key it offered, and carries the microphone.
  media::SrtpKey engine_key{};
  std::copy(offer->crypto[0].key.begin(), offer->crypto[0].key.end(), engine_key.begin());
  auto from_engine = media::SrtpStream::create(media::SrtpStream::Direction::Inbound, engine_key);
  std::array<int16_t, 160> capture;
  capture.fill(1200);
  bool heard = false;
  net::Endpoint engine_media;
  for (int n = 0; n < 20 && !heard; ++n) {
    CHECK_EQ(ketphone_audio_capture(engine.get(), capture.data(), capture.size()), capture.size());
    auto packet = receive_packet(*media);
    CHECK(packet.has_value());
    engine_media = packet->from;
    const auto plain = from_engine->unprotect(packet->bytes, packet->size);
    CHECK(plain.has_value());
    const auto rtp = media::parse_rtp(std::span<const uint8_t>(packet->bytes).first(*plain));
    CHECK(rtp.has_value());
    CHECK_EQ(rtp->payload.size(), size_t{160});
    heard = rtp->payload.front() != 0xd5;  // 0xd5 is A-law silence
  }
  CHECK(heard);

  // Plain RTP from anyone is dropped; only packets under the server's key are played.
  std::array<uint8_t, 160> payload;
  payload.fill(0xfa);  // A-law for 1008
  auto to_engine = media::SrtpStream::create(media::SrtpStream::Direction::Outbound, *server_key);
  for (uint16_t n = 0; n < 24; ++n) {
    alignas(4) std::array<uint8_t, 172 + media::kSrtpTrailerRoom> packet{};
    CHECK_EQ(media::write_rtp(packet, {8, false, n, uint32_t{n} * 160, 4321}, payload), size_t{172});
    size_t size = 172;
    if (n >= 12) size = to_engine->protect(packet, size);
    CHECK(media->send_to(std::span<const uint8_t>(packet).first(size), engine_media));
    std::this_thread::sleep_for(20ms);
    if (n == 11) CHECK(!playout_shows(engine.get(), 1008, 300ms));
  }
  CHECK(playout_shows(engine.get(), 1008, 2s));

  CHECK(ketphone_hangup(engine.get(), id) == KETPHONE_OK);
  session->send(reply(next_request(*session, "BYE")));
  CHECK(await([&] { return events.ended.load() == 1; }));

  // The server drops the connection: registration is lost, then comes back on a new connection.
  session.reset();
  CHECK(await([&] { return events.seen().size() == 2; }));
  CHECK_EQ(events.seen().back(), 503);
  session = server.accept(5s);
  CHECK(session != nullptr);
  register_over(*session, events, 3);

  // Destroying the engine unregisters over the connection.
  std::thread destroyer([&] { engine.reset(); });
  const auto unregister = next_request(*session, "REGISTER");
  CHECK_EQ(std::string(*unregister.header("expires")), std::string("0"));
  session->send(reply(unregister));
  destroyer.join();
}

TEST(tls_c_api_does_not_register_with_a_server_it_does_not_trust) {
  TestPki pki({"localhost"});
  TestPki stranger({"localhost"});
  TlsServer server(pki);
  Events events;
  auto engine = tls_engine(server, stranger, events);
  CHECK(engine != nullptr);
  CHECK(ketphone_register(engine.get()) == KETPHONE_OK);
  CHECK(server.accept() == nullptr);
  CHECK(await([&] { return !events.seen().empty(); }, 5s));
  CHECK(events.seen().front() != 200);
  // It keeps trying, and keeps refusing.
  CHECK(server.accept(5s) == nullptr);
  const auto seen = events.seen();
  CHECK(std::find(seen.begin(), seen.end(), 200) == seen.end());
}

TEST(tls_c_api_refuses_unusable_tls_settings) {
  TestPki pki({"localhost"});
  TlsServer server(pki);
  Events events;
  ketphone_config config{};
  config.struct_size = sizeof(config);
  config.server_host = "127.0.0.1";
  config.server_port = server.port();
  config.extension = "1001";
  config.password = "secret";
  config.transport = KETPHONE_TRANSPORT_TLS;
  config.tls_trust_anchors = "not a certificate";
  CHECK(ketphone_engine_create(&config, Events::record, &events) == nullptr);
  config.tls_trust_anchors = nullptr;
  // What a C caller could pass; C++ cannot even name it as the enum.
  const std::underlying_type_t<ketphone_transport> unknown = 7;
  std::memcpy(&config.transport, &unknown, sizeof(unknown));
  CHECK(ketphone_engine_create(&config, Events::record, &events) == nullptr);
}

#endif  // KETPHONE_TEST_TLS
