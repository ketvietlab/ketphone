// Real loopback sockets: exercise the C API, SIP headers, SDP and two-way RTP over IPv6.
// These are not a substitute for an iPhone on an IPv6-only DNS64/NAT64 network.
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstring>
#include <memory>
#include <thread>
#include <vector>

#include "check.hpp"
#include "ketphone/ketphone.h"
#include "media/rtp.hpp"
#include "net/udp_socket.hpp"
#include "sip/message.hpp"
#include "sip/sdp.hpp"

namespace {
using namespace std::chrono_literals;
using namespace ketphone;

struct Datagram {
  std::vector<uint8_t> bytes;
  sockaddr_storage source{};
  socklen_t length = sizeof(source);
  std::string text() const { return {bytes.begin(), bytes.end()}; }
};

class Peer {
 public:
  explicit Peer(int family) {
    fd_ = ::socket(family, SOCK_DGRAM, 0);
    CHECK(fd_ >= 0);
    sockaddr_storage address{};
    socklen_t length;
    if (family == AF_INET6) {
      sockaddr_in6 ip{};
      ip.sin6_family = AF_INET6;
      ip.sin6_addr = in6addr_loopback;
      std::memcpy(&address, &ip, sizeof(ip));
      length = sizeof(ip);
    } else {
      sockaddr_in ip{};
      ip.sin_family = AF_INET;
      ip.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
      std::memcpy(&address, &ip, sizeof(ip));
      length = sizeof(ip);
    }
    CHECK(::bind(fd_, reinterpret_cast<const sockaddr*>(&address), length) == 0);
    CHECK(::getsockname(fd_, reinterpret_cast<sockaddr*>(&address), &length) == 0);
    if (family == AF_INET6) {
      sockaddr_in6 ip{};
      std::memcpy(&ip, &address, sizeof(ip));
      port_ = ntohs(ip.sin6_port);
    } else {
      sockaddr_in ip{};
      std::memcpy(&ip, &address, sizeof(ip));
      port_ = ntohs(ip.sin_port);
    }
    timeval timeout{2, 0};
    CHECK(::setsockopt(fd_, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0);
  }
  ~Peer() { ::close(fd_); }
  Peer(const Peer&) = delete;
  Peer& operator=(const Peer&) = delete;
  uint16_t port() const { return port_; }

  Datagram receive() {
    Datagram out;
    out.bytes.resize(65536);
    const auto size = ::recvfrom(fd_, out.bytes.data(), out.bytes.size(), 0,
                                 reinterpret_cast<sockaddr*>(&out.source), &out.length);
    CHECK(size > 0);
    out.bytes.resize(static_cast<size_t>(size));
    return out;
  }
  void send(std::span<const uint8_t> bytes, const Datagram& to) {
    CHECK_EQ(::sendto(fd_, bytes.data(), bytes.size(), 0, reinterpret_cast<const sockaddr*>(&to.source), to.length),
             static_cast<ssize_t>(bytes.size()));
  }
  void send(const std::string& text, const Datagram& to) {
    send({reinterpret_cast<const uint8_t*>(text.data()), text.size()}, to);
  }
  void reply(const Datagram& request, const std::string& body = {}) {
    const auto message = sip::parse_message(request.text());
    CHECK(message.has_value());
    std::string response = "SIP/2.0 200 OK\r\n";
    for (const auto via : message->header_all("via")) response += "Via: " + std::string(via) + "\r\n";
    response += "From: " + std::string(*message->header("from")) + "\r\n";
    std::string to(*message->header("to"));
    if (to.find(";tag=") == std::string::npos) to += ";tag=peer";
    response += "To: " + to + "\r\nCall-ID: " + std::string(*message->header("call-id")) + "\r\n";
    response += "CSeq: " + std::string(*message->header("cseq")) + "\r\n";
    response += "Contact: <sip:peer@[::1]:" + std::to_string(port_) + ">\r\n";
    if (!body.empty()) response += "Content-Type: application/sdp\r\n";
    response += "Content-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;
    send(response, request);
  }

 private:
  int fd_ = -1;
  uint16_t port_ = 0;
};

struct Events {
  std::atomic<int> registered{0};
  std::atomic<int> answered{0};
  std::atomic<ketphone_call_id> incoming{0};
  static void record(const ketphone_event* e, void* context) {
    auto& self = *static_cast<Events*>(context);
    if (e->kind == KETPHONE_EVENT_REGISTRATION && e->status_code == 200) ++self.registered;
    if (e->kind == KETPHONE_EVENT_CALL_ANSWERED) ++self.answered;
    if (e->kind == KETPHONE_EVENT_CALL_INCOMING) self.incoming = e->call_id;
  }
};

template<class Predicate>
void await(Predicate ready) {
  const auto deadline = std::chrono::steady_clock::now() + 2s;
  while (std::chrono::steady_clock::now() < deadline) {
    if (ready()) return;
    std::this_thread::sleep_for(5ms);
  }
  CHECK(ready());
}

using Engine = std::unique_ptr<ketphone_engine, decltype(&ketphone_engine_destroy)>;
Engine engine_for(Peer& peer, Events& events) {
  ketphone_config config{};
  config.struct_size = sizeof(config);
  config.server_host = "::1";
  config.server_port = peer.port();
  config.extension = "1001";
  config.password = "test";
  Engine engine(ketphone_engine_create(&config, Events::record, &events), ketphone_engine_destroy);
  CHECK(engine != nullptr);
  return engine;
}

Datagram register_engine(Peer& peer, Engine& engine, Events& events) {
  CHECK(ketphone_register(engine.get()) == KETPHONE_OK);
  const auto packet = peer.receive();
  const auto message = sip::parse_message(packet.text());
  CHECK(message.has_value());
  CHECK_EQ(message->method, std::string("REGISTER"));
  CHECK_EQ(message->uri, std::string("sip:[::1]"));
  CHECK(message->header("via")->starts_with("SIP/2.0/UDP [::1]:"));
  CHECK(message->header("contact")->starts_with("<sip:1001@[::1]:"));
  peer.reply(packet);
  await([&] { return events.registered.load() == 1; });
  return packet;
}

void unregister_engine(Peer& peer, Engine& engine) {
  CHECK(ketphone_unregister(engine.get()) == KETPHONE_OK);
  const auto packet = peer.receive();
  const auto message = sip::parse_message(packet.text());
  CHECK(message.has_value());
  CHECK_EQ(std::string(*message->header("expires")), std::string("0"));
  peer.reply(packet);
}

void verify_audio(Peer& media_peer, Engine& engine) {
  std::array<int16_t, 160> capture;
  capture.fill(1200);
  CHECK_EQ(ketphone_audio_capture(engine.get(), capture.data(), capture.size()), capture.size());
  auto packet = media_peer.receive();
  auto rtp = media::parse_rtp(packet.bytes);
  CHECK(rtp.has_value());
  CHECK_EQ(rtp->header.payload_type, uint8_t{8});
  CHECK_EQ(rtp->payload.size(), size_t{160});
  // Wait until the microphone frame reaches the peer rather than accepting silence packets.
  for (int n = 0; n < 10 && rtp->payload.front() == 0xd5; ++n) {
    packet = media_peer.receive();
    rtp = media::parse_rtp(packet.bytes);
    CHECK(rtp.has_value());
  }
  CHECK(rtp->payload.front() != 0xd5);
  std::array<uint8_t, 160> payload;
  payload.fill(0xfa);  // non-silent A-law samples from the remote microphone
  std::array<uint8_t, 172> reply{};
  for (uint16_t n = 0; n < 12; ++n) {
    CHECK_EQ(media::write_rtp(reply, {8, false, n, uint32_t{n} * 160, 1234}, payload), reply.size());
    media_peer.send(reply, packet);
    std::this_thread::sleep_for(20ms);
  }
  std::array<int16_t, 160> playout{};
  await([&] {
    ketphone_audio_playout(engine.get(), playout.data(), playout.size());
    return std::any_of(playout.begin(), playout.end(), [](int16_t sample) { return sample == 1008; });
  });
  ketphone_media_stats stats{};
  CHECK(ketphone_media_stats_get(engine.get(), &stats) == KETPHONE_OK);
  CHECK(stats.packets_received > 0);
  CHECK(stats.packets_sent > 0);
}

void outgoing_call(int media_family) {
  Peer signaling(AF_INET6);
  Peer media_peer(media_family);
  Events events;
  auto engine = engine_for(signaling, events);
  register_engine(signaling, engine, events);
  ketphone_call_id id = 0;
  CHECK(ketphone_call(engine.get(), "1002", &id) == KETPHONE_OK);
  const auto invite = signaling.receive();
  const auto message = sip::parse_message(invite.text());
  CHECK(message.has_value());
  CHECK_EQ(message->method, std::string("INVITE"));
  CHECK_EQ(message->uri, std::string("sip:1002@[::1]"));
  const auto offer = sip::parse_audio(message->body);
  CHECK(offer.has_value());
  CHECK_EQ(offer->address, std::string("::1"));
  CHECK(message->body.find("c=IN IP6 ::1") != std::string::npos);
  signaling.reply(invite, sip::build_audio_sdp(media_family == AF_INET6 ? "::1" : "127.0.0.1", media_peer.port(), 1, 1));
  const auto ack = sip::parse_message(signaling.receive().text());
  CHECK(ack.has_value());
  CHECK_EQ(ack->method, std::string("ACK"));
  await([&] { return events.answered.load() == 1; });
  verify_audio(media_peer, engine);
  CHECK(ketphone_hangup(engine.get(), id) == KETPHONE_OK);
  const auto bye = signaling.receive();
  CHECK_EQ(sip::parse_message(bye.text())->method, std::string("BYE"));
  signaling.reply(bye);
  unregister_engine(signaling, engine);
}
}  // namespace

TEST(ipv6_udp_endpoint_round_trip_preserves_scope_and_port) {
  const auto endpoints = net::resolve_all("::1", 5070);
  CHECK(!endpoints.empty());
  CHECK_EQ(endpoints.front().family, AF_INET6);
  auto endpoint = endpoints.front();
  endpoint.scope_id = 7;
  const auto raw = endpoint.to_sockaddr();
  const auto decoded = net::Endpoint::from_sockaddr(reinterpret_cast<const sockaddr*>(&raw), endpoint.sockaddr_length());
  CHECK(decoded.has_value());
  CHECK(*decoded == endpoint);
  CHECK_EQ(endpoint.address_string(), std::string("::1%7"));
  CHECK(!net::Endpoint::from_sockaddr(reinterpret_cast<const sockaddr*>(&raw), 1));
  CHECK(!net::UdpSocket::open(AF_UNSPEC));
}

TEST(ipv6_udp_socket_exchanges_datagrams_and_rejects_family_mismatch) {
  Peer peer(AF_INET6);
  auto socket = net::UdpSocket::open(AF_INET6);
  const auto endpoint = net::resolve("::1", peer.port());
  CHECK(socket.has_value());
  CHECK(endpoint.has_value());
  CHECK(socket->connect(*endpoint));
  CHECK_EQ(socket->local()->address_string(), std::string("::1"));
  const std::array<uint8_t, 3> bytes{1, 2, 3};
  CHECK(socket->send(bytes));
  const auto request = peer.receive();
  CHECK(request.bytes == std::vector<uint8_t>(bytes.begin(), bytes.end()));
  peer.send(bytes, request);
  std::array<uint8_t, 10> received{};
  net::Endpoint from;
  await([&] { return socket->receive(received, &from).value_or(0) == bytes.size(); });
  CHECK(from == *endpoint);
  CHECK(std::equal(bytes.begin(), bytes.end(), received.begin()));
  auto ipv4 = net::UdpSocket::open(AF_INET);
  CHECK(ipv4.has_value());
  CHECK(!ipv4->connect(*endpoint));
  CHECK(!ipv4->send_to(bytes, *endpoint));
}

TEST(ipv6_c_api_outgoing_call_exchanges_non_silent_audio_both_ways) { outgoing_call(AF_INET6); }

TEST(ipv6_c_api_signaling_with_ipv4_media_on_dual_stack) { outgoing_call(AF_INET); }

TEST(ipv6_c_api_incoming_call_answers_with_ipv6_sdp_and_audio) {
  Peer signaling(AF_INET6);
  Peer media_peer(AF_INET6);
  Events events;
  auto engine = engine_for(signaling, events);
  const auto registered = register_engine(signaling, engine, events);
  const auto registration = sip::parse_message(registered.text());
  const auto contact = sip::uri_of(*registration->header("contact"));
  const auto body = sip::build_audio_sdp("::1", media_peer.port(), 2, 1);
  const std::string invite = "INVITE " + contact + " SIP/2.0\r\n"
      "Via: SIP/2.0/UDP [::1]:" + std::to_string(signaling.port()) + ";branch=z9hG4bKincoming;rport\r\n"
      "From: <sip:1002@[::1]>;tag=peer\r\nTo: <sip:1001@[::1]>\r\n"
      "Call-ID: ipv6-incoming\r\nCSeq: 1 INVITE\r\nContact: <sip:1002@[::1]>\r\n"
      "Content-Type: application/sdp\r\nContent-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;
  signaling.send(invite, registered);
  await([&] { return events.incoming.load() != 0; });
  CHECK(ketphone_answer(engine.get(), events.incoming.load()) == KETPHONE_OK);
  Datagram answer;
  sip::Message parsed;
  for (int n = 0; n < 4; ++n) {
    answer = signaling.receive();
    const auto candidate = sip::parse_message(answer.text());
    CHECK(candidate.has_value());
    if (candidate->status == 200) { parsed = *candidate; break; }
  }
  CHECK_EQ(parsed.status, 200);
  CHECK(parsed.body.find("c=IN IP6 ::1") != std::string::npos);
  const std::string ack = "ACK " + contact + " SIP/2.0\r\n"
      "Via: SIP/2.0/UDP [::1]:" + std::to_string(signaling.port()) + ";branch=z9hG4bKack;rport\r\n"
      "From: " + std::string(*parsed.header("from")) + "\r\nTo: " + std::string(*parsed.header("to")) + "\r\n"
      "Call-ID: ipv6-incoming\r\nCSeq: 1 ACK\r\nContent-Length: 0\r\n\r\n";
  signaling.send(ack, registered);
  verify_audio(media_peer, engine);
  CHECK(ketphone_hangup(engine.get(), events.incoming.load()) == KETPHONE_OK);
  const auto bye = signaling.receive();
  CHECK_EQ(sip::parse_message(bye.text())->method, std::string("BYE"));
  signaling.reply(bye);
  unregister_engine(signaling, engine);
}
