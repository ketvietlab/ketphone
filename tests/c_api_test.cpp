// The C API end to end over loopback UDP, with a minimal scripted server in the test.
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <cstring>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "check.hpp"
#include "ketphone/ketphone.h"
#include "sip/message.hpp"

namespace {

using namespace std::chrono_literals;

// Answers REGISTER with 200 and counts what it saw; enough to check the engine's plumbing.
class TinyServer {
 public:
  TinyServer() {
    fd_ = ::socket(AF_INET, SOCK_DGRAM, 0);
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    ::bind(fd_, reinterpret_cast<sockaddr*>(&address), sizeof(address));
    socklen_t length = sizeof(address);
    ::getsockname(fd_, reinterpret_cast<sockaddr*>(&address), &length);
    port_ = ntohs(address.sin_port);
    timeval timeout{0, 100000};
    ::setsockopt(fd_, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    thread_ = std::thread([this] { run(); });
  }

  ~TinyServer() {
    running_ = false;
    thread_.join();
    ::close(fd_);
  }

  uint16_t port() const { return port_; }

  std::vector<std::string> expires_seen() {
    std::lock_guard lock(mutex_);
    return expires_;
  }

 private:
  void run() {
    char buffer[65536];
    while (running_) {
      sockaddr_in from{};
      socklen_t length = sizeof(from);
      const ssize_t size = ::recvfrom(fd_, buffer, sizeof(buffer), 0, reinterpret_cast<sockaddr*>(&from), &length);
      if (size <= 0) continue;
      const auto request = ketphone::sip::parse_message({buffer, static_cast<size_t>(size)});
      if (!request || request->is_response || request->method != "REGISTER") continue;
      {
        std::lock_guard lock(mutex_);
        expires_.emplace_back(request->header("expires").value_or(""));
      }
      std::string reply = "SIP/2.0 200 OK\r\n";
      for (const auto via : request->header_all("via")) reply += "Via: " + std::string(via) + "\r\n";
      reply += "From: " + std::string(*request->header("from")) + "\r\n";
      reply += "To: " + std::string(*request->header("to")) + ";tag=s\r\n";
      reply += "Call-ID: " + std::string(*request->header("call-id")) + "\r\n";
      reply += "CSeq: " + std::string(*request->header("cseq")) + "\r\n";
      reply += "Expires: " + std::string(request->header("expires").value_or("0")) + "\r\n";
      reply += "Content-Length: 0\r\n\r\n";
      ::sendto(fd_, reply.data(), reply.size(), 0, reinterpret_cast<sockaddr*>(&from), length);
    }
  }

  int fd_ = -1;
  uint16_t port_ = 0;
  std::atomic<bool> running_{true};
  std::thread thread_;
  std::mutex mutex_;
  std::vector<std::string> expires_;
};

struct Recorder {
  std::mutex mutex;
  std::vector<ketphone_event> events;
  ketphone_engine* engine = nullptr;
  ketphone_result call_from_callback = KETPHONE_OK;
};

void record(const ketphone_event* event, void* context) {
  auto* recorder = static_cast<Recorder*>(context);
  // Calling back into the engine from the callback must not deadlock.
  ketphone_call_id ignored = 0;
  const ketphone_result result = ketphone_call(recorder->engine, "bad target", &ignored);
  std::lock_guard lock(recorder->mutex);
  recorder->call_from_callback = result;
  recorder->events.push_back(*event);
}

ketphone_config config_for(uint16_t port) {
  ketphone_config config{};
  config.struct_size = sizeof(config);
  config.server_host = "127.0.0.1";
  config.server_port = port;
  config.extension = "1001";
  config.password = "secret";
  return config;
}

}  // namespace

TEST(c_api_rejects_bad_arguments) {
  CHECK(ketphone_engine_create(nullptr, nullptr, nullptr) == nullptr);
  ketphone_config config = config_for(5060);
  config.struct_size = 4;
  CHECK(ketphone_engine_create(&config, nullptr, nullptr) == nullptr);
  config = config_for(5060);
  config.extension = "";
  CHECK(ketphone_engine_create(&config, nullptr, nullptr) == nullptr);
  CHECK(ketphone_register(nullptr) == KETPHONE_ERROR_INVALID_ARGUMENT);
  CHECK(std::strlen(ketphone_version()) > 0);
}

TEST(c_api_registers_over_udp_and_unregisters_on_destroy) {
  TinyServer server;
  Recorder recorder;
  const ketphone_config config = config_for(server.port());
  recorder.engine = ketphone_engine_create(&config, record, &recorder);
  CHECK(recorder.engine != nullptr);
  CHECK(ketphone_register(recorder.engine) == KETPHONE_OK);

  const auto deadline = std::chrono::steady_clock::now() + 3s;
  for (;;) {
    {
      std::lock_guard lock(recorder.mutex);
      if (!recorder.events.empty()) break;
    }
    CHECK(std::chrono::steady_clock::now() < deadline);
    std::this_thread::sleep_for(10ms);
  }
  {
    std::lock_guard lock(recorder.mutex);
    CHECK_EQ(int{recorder.events[0].kind}, int{KETPHONE_EVENT_REGISTRATION});
    CHECK_EQ(recorder.events[0].status_code, 200);
    CHECK_EQ(int{recorder.call_from_callback}, int{KETPHONE_ERROR_INVALID_ARGUMENT});
  }
  CHECK_EQ(int{ketphone_hangup(recorder.engine, 12345)}, int{KETPHONE_ERROR_NOT_FOUND});

  int16_t silence[160];
  CHECK_EQ(ketphone_audio_playout(recorder.engine, silence, 160), size_t{0});
  CHECK_EQ(int{silence[0]}, 0);

  ketphone_engine_destroy(recorder.engine);
  const auto expires = server.expires_seen();
  CHECK_EQ(expires.size(), size_t{2});
  CHECK_EQ(expires.back(), std::string("0"));
}
