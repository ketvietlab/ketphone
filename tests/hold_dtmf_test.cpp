// Hold, resume and DTMF through the C API over loopback UDP, against a scripted server that answers
// the way Asterisk does: the INVITE with telephone events on 101, each re-INVITE with the mirror of
// its direction.
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "check.hpp"
#include "ketphone/ketphone.h"
#include "media/rtp.hpp"
#include "sip/message.hpp"

namespace {

using namespace std::chrono_literals;
using ketphone::sip::Message;

sockaddr_in loopback_socket(int& fd) {
  fd = ::socket(AF_INET, SOCK_DGRAM, 0);
  sockaddr_in address{};
  address.sin_family = AF_INET;
  address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  ::bind(fd, reinterpret_cast<sockaddr*>(&address), sizeof(address));
  socklen_t length = sizeof(address);
  ::getsockname(fd, reinterpret_cast<sockaddr*>(&address), &length);
  timeval timeout{0, 20000};
  ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
  return address;
}

template <typename Condition>
bool wait_for(Condition condition) {
  const auto deadline = std::chrono::steady_clock::now() + 3s;
  while (!condition()) {
    if (std::chrono::steady_clock::now() > deadline) return false;
    std::this_thread::sleep_for(5ms);
  }
  return true;
}

struct RtpSeen {
  uint8_t payload_type = 0;
  std::vector<uint8_t> payload;
};

class Server {
 public:
  Server() {
    sip_address_ = loopback_socket(sip_fd_);
    rtp_address_ = loopback_socket(rtp_fd_);
    sip_thread_ = std::thread([this] { run_sip(); });
    rtp_thread_ = std::thread([this] { run_rtp(); });
  }

  ~Server() {
    running_ = false;
    sip_thread_.join();
    rtp_thread_.join();
    ::close(sip_fd_);
    ::close(rtp_fd_);
  }

  uint16_t port() const { return ntohs(sip_address_.sin_port); }

  std::vector<std::string> reinvite_bodies() {
    std::lock_guard lock(mutex_);
    return reinvites_;
  }
  size_t acks() {
    std::lock_guard lock(mutex_);
    return acks_;
  }
  std::vector<RtpSeen> rtp() {
    std::lock_guard lock(mutex_);
    return rtp_;
  }

 private:
  std::string sdp(const std::string& direction) const {
    return "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=Asterisk\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\nm=audio " +
           std::to_string(ntohs(rtp_address_.sin_port)) +
           " RTP/AVP 8 101\r\na=rtpmap:8 PCMA/8000\r\na=rtpmap:101 telephone-event/8000\r\n"
           "a=fmtp:101 0-16\r\na=ptime:20\r\na=" + direction + "\r\n";
  }

  void reply(const Message& request, int status, const std::string& extra = {}, const std::string& body = {}) {
    std::string out = "SIP/2.0 " + std::to_string(status) + " X\r\n";
    for (const auto via : request.header_all("via")) out += "Via: " + std::string(via) + "\r\n";
    out += "From: " + std::string(*request.header("from")) + "\r\n";
    std::string to(*request.header("to"));
    if (to.find(";tag=") == std::string::npos) to += ";tag=srv";
    out += "To: " + to + "\r\n";
    out += "Call-ID: " + std::string(*request.header("call-id")) + "\r\n";
    out += "CSeq: " + std::string(*request.header("cseq")) + "\r\n";
    out += extra;
    if (!body.empty()) out += "Content-Type: application/sdp\r\n";
    out += "Content-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;
    ::sendto(sip_fd_, out.data(), out.size(), 0, reinterpret_cast<sockaddr*>(&engine_), sizeof(engine_));
  }

  void run_sip() {
    char buffer[65536];
    while (running_) {
      sockaddr_in from{};
      socklen_t length = sizeof(from);
      const ssize_t size = ::recvfrom(sip_fd_, buffer, sizeof(buffer), 0, reinterpret_cast<sockaddr*>(&from), &length);
      if (size <= 0) continue;
      const auto message = ketphone::sip::parse_message({buffer, static_cast<size_t>(size)});
      if (!message || message->is_response) continue;
      std::lock_guard lock(mutex_);
      engine_ = from;
      const std::string contact = "Contact: <sip:asterisk@127.0.0.1:" + std::to_string(port()) + ">\r\n";
      if (message->method == "REGISTER") {
        reply(*message, 200, "Expires: " + std::string(message->header("expires").value_or("0")) + "\r\n");
      } else if (message->method == "INVITE") {
        const bool reinvite = message->header("to")->find(";tag=") != std::string_view::npos;
        std::string direction = "sendrecv";
        if (reinvite) {
          reinvites_.push_back(message->body);
          if (message->body.find("a=sendonly") != std::string::npos) direction = "recvonly";
          if (message->body.find("a=inactive") != std::string::npos) direction = "inactive";
          if (message->body.find("a=recvonly") != std::string::npos) direction = "sendonly";
        }
        reply(*message, 200, contact, sdp(direction));
      } else if (message->method == "ACK") {
        ++acks_;
      } else if (message->method == "BYE") {
        reply(*message, 200);
      }
    }
  }

  void run_rtp() {
    uint8_t buffer[2048];
    while (running_) {
      const ssize_t size = ::recv(rtp_fd_, buffer, sizeof(buffer), 0);
      if (size <= 0) continue;
      const auto packet = ketphone::media::parse_rtp({buffer, static_cast<size_t>(size)});
      if (!packet) continue;
      std::lock_guard lock(mutex_);
      rtp_.push_back({packet->header.payload_type, {packet->payload.begin(), packet->payload.end()}});
    }
  }

  int sip_fd_ = -1;
  int rtp_fd_ = -1;
  sockaddr_in sip_address_{};
  sockaddr_in rtp_address_{};
  sockaddr_in engine_{};
  std::atomic<bool> running_{true};
  std::thread sip_thread_;
  std::thread rtp_thread_;
  std::mutex mutex_;
  std::vector<std::string> reinvites_;
  size_t acks_ = 0;
  std::vector<RtpSeen> rtp_;
};

struct Events {
  std::mutex mutex;
  std::vector<ketphone_event> list;

  std::vector<ketphone_event> of(ketphone_event_kind kind) {
    std::lock_guard lock(mutex);
    std::vector<ketphone_event> out;
    for (const auto& event : list) {
      if (event.kind == kind) out.push_back(event);
    }
    return out;
  }
};

void record(const ketphone_event* event, void* context) {
  auto* events = static_cast<Events*>(context);
  std::lock_guard lock(events->mutex);
  ketphone_event copy = *event;
  copy.remote = copy.remote_display_name = copy.correlation_id = nullptr;  // valid only during the callback
  events->list.push_back(copy);
}

// A registered engine with a connected outgoing call.
struct Connected {
  Server server;
  Events events;
  ketphone_engine* engine = nullptr;
  ketphone_call_id call = 0;

  Connected() {
    ketphone_config config{};
    config.struct_size = sizeof(config);
    config.server_host = "127.0.0.1";
    config.server_port = server.port();
    config.extension = "1001";
    config.password = "secret";
    engine = ketphone_engine_create(&config, record, &events);
    CHECK(engine != nullptr);
    CHECK(ketphone_register(engine) == KETPHONE_OK);
    CHECK(wait_for([this] { return !events.of(KETPHONE_EVENT_REGISTRATION).empty(); }));
    CHECK(ketphone_call(engine, "1002", &call) == KETPHONE_OK);
    CHECK(wait_for([this] { return !events.of(KETPHONE_EVENT_CALL_ANSWERED).empty(); }));
  }

  ~Connected() { ketphone_engine_destroy(engine); }

  size_t audio_packets() {
    size_t n = 0;
    for (const auto& packet : server.rtp()) n += packet.payload_type == 8;
    return n;
  }
};

}  // namespace

TEST(c_api_sends_keys_as_rfc4733_events_on_the_negotiated_type) {
  Connected connected;
  CHECK(wait_for([&] { return connected.audio_packets() > 2; }));
  CHECK(ketphone_send_dtmf(connected.engine, connected.call, nullptr, 0) == KETPHONE_ERROR_INVALID_ARGUMENT);
  CHECK(ketphone_send_dtmf(connected.engine, connected.call, "1x", 0) == KETPHONE_ERROR_INVALID_ARGUMENT);
  CHECK(ketphone_send_dtmf(connected.engine, connected.call + 1, "1", 0) == KETPHONE_ERROR_NOT_FOUND);
  CHECK(ketphone_send_dtmf(connected.engine, connected.call, "1#", 60) == KETPHONE_OK);

  // Each key: 60 ms in three packets, the last of them and two more marked as the end.
  const auto ends_of = [&](uint8_t code) {
    size_t ends = 0;
    for (const auto& packet : connected.server.rtp()) {
      if (packet.payload_type == 101 && packet.payload.size() == 4 && packet.payload[0] == code) {
        ends += (packet.payload[1] & 0x80) != 0;
      }
    }
    return ends;
  };
  CHECK(wait_for([&] { return ends_of(11) == 3; }));
  CHECK_EQ(ends_of(1), size_t{3});
  size_t events = 0;
  uint16_t last_duration = 0;
  for (const auto& packet : connected.server.rtp()) {
    if (packet.payload_type != 101) continue;
    ++events;
    if (packet.payload[0] == 1) last_duration = static_cast<uint16_t>(packet.payload[2] << 8 | packet.payload[3]);
  }
  CHECK_EQ(events, size_t{10});  // three a key, the third the first of three end packets
  CHECK_EQ(last_duration, uint16_t{480});
  // Nothing but A-law and the events went out.
  for (const auto& packet : connected.server.rtp()) CHECK(packet.payload_type == 8 || packet.payload_type == 101);
}

TEST(c_api_holds_and_resumes_with_reinvites_and_media_follows) {
  Connected connected;
  CHECK(wait_for([&] { return connected.audio_packets() > 2; }));
  CHECK(ketphone_hold(connected.engine, connected.call + 1) == KETPHONE_ERROR_NOT_FOUND);

  CHECK(ketphone_hold(connected.engine, connected.call) == KETPHONE_OK);
  CHECK(wait_for([&] { return connected.events.of(KETPHONE_EVENT_CALL_HOLD).size() == 1; }));
  const auto held = connected.events.of(KETPHONE_EVENT_CALL_HOLD).at(0);
  CHECK_EQ(held.call_id, connected.call);
  CHECK_EQ(held.status_code, 200);
  CHECK_EQ(held.hold, uint32_t{KETPHONE_HOLD_LOCAL});
  CHECK(connected.server.reinvite_bodies().at(0).find("a=sendonly\r\n") != std::string::npos);
  CHECK(wait_for([&] { return connected.server.acks() == 2; }));  // the INVITE's and the re-INVITE's
  CHECK(ketphone_send_dtmf(connected.engine, connected.call, "1", 0) == KETPHONE_ERROR_STATE);

  // Held: nothing is sent. Allow a packet already on its way.
  std::this_thread::sleep_for(60ms);
  const size_t at_hold = connected.audio_packets();
  std::this_thread::sleep_for(300ms);
  CHECK(connected.audio_packets() <= at_hold + 1);

  CHECK(ketphone_resume(connected.engine, connected.call) == KETPHONE_OK);
  CHECK(wait_for([&] { return connected.events.of(KETPHONE_EVENT_CALL_HOLD).size() == 2; }));
  const auto resumed = connected.events.of(KETPHONE_EVENT_CALL_HOLD).at(1);
  CHECK_EQ(resumed.status_code, 200);
  CHECK_EQ(resumed.hold, uint32_t{KETPHONE_HOLD_NONE});
  CHECK(connected.server.reinvite_bodies().at(1).find("a=sendrecv\r\n") != std::string::npos);
  const size_t at_resume = connected.audio_packets();
  CHECK(wait_for([&] { return connected.audio_packets() > at_resume + 5; }));
  CHECK(ketphone_send_dtmf(connected.engine, connected.call, "1", 0) == KETPHONE_OK);

  // Other events carry no hold bits.
  for (const auto& event : connected.events.of(KETPHONE_EVENT_CALL_ANSWERED)) CHECK_EQ(event.hold, uint32_t{0});
  CHECK(ketphone_hangup(connected.engine, connected.call) == KETPHONE_OK);
}
