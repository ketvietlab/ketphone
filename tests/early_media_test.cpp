// What a caller hears while an outgoing call is still ringing, through the C API over loopback UDP
// against a scripted server that plays the part of Asterisk (and, behind it, a carrier).
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <mutex>
#include <numbers>
#include <string>
#include <thread>
#include <vector>

#include "check.hpp"
#include "ketphone/ketphone.h"
#include "media/g711.hpp"
#include "media/rtp.hpp"
#include "sip/message.hpp"

namespace {

using namespace std::chrono_literals;
using ketphone::sip::Message;

sockaddr_in loopback_socket(int& fd, uint16_t port = 0) {
  fd = ::socket(AF_INET, SOCK_DGRAM, 0);
  sockaddr_in address{};
  address.sin_family = AF_INET;
  address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  address.sin_port = htons(port);
  ::bind(fd, reinterpret_cast<sockaddr*>(&address), sizeof(address));
  socklen_t length = sizeof(address);
  ::getsockname(fd, reinterpret_cast<sockaddr*>(&address), &length);
  timeval timeout{0, 50000};
  ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
  return address;
}

// Registers the engine, then answers an INVITE with whatever the test tells it to send.
class CallServer {
 public:
  CallServer() {
    sip_address_ = loopback_socket(sip_fd_);
    rtp_address_ = loopback_socket(rtp_fd_);
    thread_ = std::thread([this] { run(); });
  }

  ~CallServer() {
    running_ = false;
    thread_.join();
    ::close(sip_fd_);
    ::close(rtp_fd_);
  }

  uint16_t port() const { return ntohs(sip_address_.sin_port); }

  bool wait_for_invite() { return wait_until([this] { return have_invite_.load(); }); }

  // A response to the INVITE; `sdp` empty sends none.
  void reply(int status, const std::string& sdp = {}) {
    std::lock_guard lock(mutex_);
    std::string out = "SIP/2.0 " + std::to_string(status) + " X\r\n";
    for (const auto via : invite_.header_all("via")) out += "Via: " + std::string(via) + "\r\n";
    out += "From: " + std::string(*invite_.header("from")) + "\r\n";
    out += "To: " + std::string(*invite_.header("to")) + ";tag=srv\r\n";
    out += "Call-ID: " + std::string(*invite_.header("call-id")) + "\r\n";
    out += "CSeq: " + std::string(*invite_.header("cseq")) + "\r\n";
    if (status == 200) out += "Contact: <sip:asterisk@127.0.0.1>\r\n";
    if (!sdp.empty()) out += "Content-Type: application/sdp\r\n";
    out += "Content-Length: " + std::to_string(sdp.size()) + "\r\n\r\n" + sdp;
    send_to_engine(out);
  }

  // The server's answer or early-media SDP: PCMA to the port the server's RTP socket listens on.
  std::string sdp() const {
    return "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=Asterisk\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\nm=audio " +
           std::to_string(ntohs(rtp_address_.sin_port)) +
           " RTP/AVP 8 101\r\na=rtpmap:8 PCMA/8000\r\na=sendrecv\r\n";
  }

  // One 20 ms packet of a sine at `hertz`, as the carrier's own ringing tone would arrive.
  void send_rtp_tone(double hertz) {
    std::vector<int16_t> samples(160);
    for (auto& sample : samples) {
      sample = static_cast<int16_t>(8000 * std::sin(2 * std::numbers::pi * hertz * static_cast<double>(tone_n_++) / 8000));
    }
    std::vector<uint8_t> payload(160);
    ketphone::media::alaw_encode(samples.data(), samples.size(), payload.data());
    ketphone::media::RtpHeader header;
    header.payload_type = 8;
    header.sequence = rtp_sequence_++;
    header.timestamp = rtp_timestamp_;
    rtp_timestamp_ += 160;
    header.ssrc = 0x1234;
    std::vector<uint8_t> packet(ketphone::media::kRtpHeaderSize + payload.size());
    ketphone::media::write_rtp(packet, header, payload);
    sockaddr_in to = engine_rtp_;
    ::sendto(rtp_fd_, packet.data(), packet.size(), 0, reinterpret_cast<sockaddr*>(&to), sizeof(to));
  }

  std::vector<std::string> methods_seen() {
    std::lock_guard lock(mutex_);
    return methods_;
  }

 private:
  template <typename Condition>
  bool wait_until(Condition condition) {
    const auto deadline = std::chrono::steady_clock::now() + 3s;
    while (!condition()) {
      if (std::chrono::steady_clock::now() > deadline) return false;
      std::this_thread::sleep_for(5ms);
    }
    return true;
  }

  void send_to_engine(const std::string& message) {
    ::sendto(sip_fd_, message.data(), message.size(), 0, reinterpret_cast<sockaddr*>(&engine_sip_),
             sizeof(engine_sip_));
  }

  std::string response_to(const Message& request, int status, const std::string& extra = {}) {
    std::string out = "SIP/2.0 " + std::to_string(status) + " X\r\n";
    for (const auto via : request.header_all("via")) out += "Via: " + std::string(via) + "\r\n";
    out += "From: " + std::string(*request.header("from")) + "\r\n";
    std::string to(*request.header("to"));
    if (to.find(";tag=") == std::string::npos) to += ";tag=srv";
    out += "To: " + to + "\r\n";
    out += "Call-ID: " + std::string(*request.header("call-id")) + "\r\n";
    out += "CSeq: " + std::string(*request.header("cseq")) + "\r\n";
    out += extra;
    out += "Content-Length: 0\r\n\r\n";
    return out;
  }

  void run() {
    char buffer[65536];
    while (running_) {
      sockaddr_in from{};
      socklen_t length = sizeof(from);
      // The engine's RTP goes to the SDP port of this socket; it is read only to keep the buffer empty.
      while (::recv(rtp_fd_, buffer, sizeof(buffer), MSG_DONTWAIT) > 0) {
      }
      const ssize_t size = ::recvfrom(sip_fd_, buffer, sizeof(buffer), 0, reinterpret_cast<sockaddr*>(&from), &length);
      if (size <= 0) continue;
      const auto message = ketphone::sip::parse_message({buffer, static_cast<size_t>(size)});
      if (!message || message->is_response) continue;
      std::lock_guard lock(mutex_);
      engine_sip_ = from;
      methods_.push_back(message->method);
      if (message->method == "REGISTER") {
        send_to_engine(response_to(*message, 200, "Expires: " + std::string(message->header("expires").value_or("0")) + "\r\n"));
      } else if (message->method == "INVITE") {
        invite_ = *message;
        // The engine's RTP port is the one in its offer; media goes there from this socket.
        const auto at = message->body.find("m=audio ");
        engine_rtp_ = loopback_target(static_cast<uint16_t>(std::stoi(message->body.substr(at + 8))));
        have_invite_ = true;
        send_to_engine(response_to(*message, 100));
      } else if (message->method == "CANCEL") {
        send_to_engine(response_to(*message, 200));
        send_to_engine(response_to(invite_, 487));
      } else if (message->method == "BYE") {
        send_to_engine(response_to(*message, 200));
      }
    }
  }

  static sockaddr_in loopback_target(uint16_t port) {
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = htons(port);
    return address;
  }

  int sip_fd_ = -1;
  int rtp_fd_ = -1;
  sockaddr_in sip_address_{};
  sockaddr_in rtp_address_{};
  sockaddr_in engine_sip_{};
  sockaddr_in engine_rtp_{};
  std::atomic<bool> running_{true};
  std::atomic<bool> have_invite_{false};
  std::thread thread_;
  std::mutex mutex_;
  Message invite_;
  std::vector<std::string> methods_;
  uint16_t rtp_sequence_ = 100;
  uint32_t rtp_timestamp_ = 8000;
  uint64_t tone_n_ = 0;
};

struct Events {
  std::mutex mutex;
  std::vector<ketphone_event> list;

  size_t count(ketphone_event_kind kind) {
    std::lock_guard lock(mutex);
    size_t n = 0;
    for (const auto& event : list) n += event.kind == kind;
    return n;
  }
};

void record(const ketphone_event* event, void* context) {
  auto* events = static_cast<Events*>(context);
  std::lock_guard lock(events->mutex);
  events->list.push_back(*event);
}

// An engine registered against the scripted server, with a call placed and the INVITE seen.
struct Caller {
  CallServer server;
  Events events;
  ketphone_engine* engine = nullptr;
  ketphone_call_id call = 0;

  Caller() {
    ketphone_config config{};
    config.struct_size = sizeof(config);
    config.server_host = "127.0.0.1";
    config.server_port = server.port();
    config.extension = "1001";
    config.password = "secret";
    engine = ketphone_engine_create(&config, record, &events);
    CHECK(engine != nullptr);
    CHECK(ketphone_register(engine) == KETPHONE_OK);
    CHECK(wait_for([this] { return events.count(KETPHONE_EVENT_REGISTRATION) > 0; }));
    CHECK(ketphone_call(engine, "1002", &call) == KETPHONE_OK);
    CHECK(server.wait_for_invite());
  }

  ~Caller() { ketphone_engine_destroy(engine); }

  template <typename Condition>
  static bool wait_for(Condition condition) {
    const auto deadline = std::chrono::steady_clock::now() + 3s;
    while (!condition()) {
      if (std::chrono::steady_clock::now() > deadline) return false;
      std::this_thread::sleep_for(5ms);
    }
    return true;
  }

  // What the speaker would play over `duration`, as the audio thread pulls it every 20 ms, with
  // the server sending one packet of `rtp_hertz` per pull when that is not 0.
  struct Heard {
    std::vector<int16_t> samples;
    size_t real = 0;
  };
  Heard listen(std::chrono::milliseconds duration, double rtp_hertz = 0) {
    Heard heard;
    const auto end = std::chrono::steady_clock::now() + duration;
    while (std::chrono::steady_clock::now() < end) {
      if (rtp_hertz > 0) server.send_rtp_tone(rtp_hertz);
      int16_t block[160];
      heard.real += ketphone_audio_playout(engine, block, 160);
      heard.samples.insert(heard.samples.end(), block, block + 160);
      std::this_thread::sleep_for(20ms);
    }
    return heard;
  }
};

// Signal power at one frequency (Goertzel), as a fraction of the signal's total power.
double share_at(const std::vector<int16_t>& samples, double hertz) {
  if (samples.empty()) return 0;
  const double w = 2 * std::numbers::pi * hertz / 8000;
  const double coefficient = 2 * std::cos(w);
  double s1 = 0;
  double s2 = 0;
  double total = 0;
  for (const int16_t sample : samples) {
    const double s0 = sample + coefficient * s1 - s2;
    s2 = s1;
    s1 = s0;
    total += static_cast<double>(sample) * sample;
  }
  if (total == 0) return 0;
  const double power = s1 * s1 + s2 * s2 - coefficient * s1 * s2;
  return 2 * power / (static_cast<double>(samples.size()) * total);
}

}  // namespace

// Before the change: nothing is played while the call rings or carries early media, and the
// speaker only gets audio once the call is answered.

TEST(engine_today_plays_nothing_on_180_without_sdp) {
  Caller caller;
  caller.server.reply(180);
  CHECK(Caller::wait_for([&] { return caller.events.count(KETPHONE_EVENT_CALL_PROGRESS) == 1; }));
  const auto heard = caller.listen(600ms);
  CHECK_EQ(heard.real, size_t{0});
}

TEST(engine_today_ignores_the_sdp_of_a_183_and_plays_nothing) {
  Caller caller;
  caller.server.reply(183, caller.server.sdp());
  CHECK(Caller::wait_for([&] { return caller.events.count(KETPHONE_EVENT_CALL_PROGRESS) == 1; }));
  const auto heard = caller.listen(600ms, 1000);
  CHECK_EQ(heard.real, size_t{0});
}

TEST(engine_plays_the_answered_call_after_a_200) {
  Caller caller;
  caller.server.reply(180);
  caller.server.reply(200, caller.server.sdp());
  CHECK(Caller::wait_for([&] { return caller.events.count(KETPHONE_EVENT_CALL_ANSWERED) == 1; }));
  const auto heard = caller.listen(600ms, 1000);
  CHECK(heard.real > 0);
  CHECK(share_at(heard.samples, 1000) > 0.5);
}
