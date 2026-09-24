// The C API: an engine owns the sockets and one network thread that drives the user agent and
// the media session. Commands from other threads run on that thread and are waited for.
#include <fcntl.h>
#include <poll.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <condition_variable>
#include <deque>
#include <functional>
#include <future>
#include <memory>
#include <mutex>
#include <thread>
#include <vector>

#include "core/user_agent.hpp"
#include "ketphone/ketphone.h"
#include "media/media_session.hpp"
#include "media/spsc_ring.hpp"
#include "net/udp_socket.hpp"
#include "sip/random.hpp"

namespace ketphone::core {
namespace {

using namespace std::chrono_literals;

constexpr Duration kFrame = 20ms;
constexpr Duration kShutdownGrace = 2s;
// 200 ms each way: enough for any audio callback size, small enough to bound added latency.
constexpr size_t kRingSamples = 1600;

ketphone_result to_result(CommandResult result) {
  switch (result) {
    case CommandResult::Ok: return KETPHONE_OK;
    case CommandResult::InvalidArgument: return KETPHONE_ERROR_INVALID_ARGUMENT;
    case CommandResult::State: return KETPHONE_ERROR_STATE;
    case CommandResult::NotFound: return KETPHONE_ERROR_NOT_FOUND;
  }
  return KETPHONE_ERROR_INTERNAL;
}

ketphone_end_reason to_c(EndReason reason) {
  switch (reason) {
    case EndReason::None: return KETPHONE_END_NONE;
    case EndReason::Local: return KETPHONE_END_LOCAL;
    case EndReason::RemoteHangup: return KETPHONE_END_REMOTE_HANGUP;
    case EndReason::RemoteCancelled: return KETPHONE_END_REMOTE_CANCELLED;
    case EndReason::Rejected: return KETPHONE_END_REJECTED;
    case EndReason::Timeout: return KETPHONE_END_TIMEOUT;
    case EndReason::MediaFailed: return KETPHONE_END_MEDIA_FAILED;
    case EndReason::Shutdown: return KETPHONE_END_SHUTDOWN;
  }
  return KETPHONE_END_NONE;
}

// RTP timestamp units (1/8000 s) since an arbitrary origin, wrapping like RTP timestamps do.
int64_t micros(TimePoint time) {
  return std::chrono::duration_cast<std::chrono::microseconds>(time.time_since_epoch()).count();
}

std::string or_default(const char* value, std::string fallback) {
  return value != nullptr && value[0] != '\0' ? std::string(value) : std::move(fallback);
}

}  // namespace

class Engine final : public UserAgentHost {
 public:
  static std::unique_ptr<Engine> create(const ketphone_config& config, ketphone_event_callback callback,
                                        void* context) {
    if (config.server_host == nullptr || config.extension == nullptr || config.password == nullptr ||
        config.server_host[0] == '\0' || config.extension[0] == '\0') {
      return nullptr;
    }
    const uint16_t port = config.server_port != 0 ? config.server_port : 5060;
    const auto server = net::resolve(config.server_host, port);
    if (!server) return nullptr;
    auto sip = net::UdpSocket::open();
    if (!sip || !sip->connect(*server)) return nullptr;
    const auto local = sip->local();
    if (!local) return nullptr;

    UserAgentConfig ua;
    ua.domain = config.server_host;
    ua.extension = config.extension;
    ua.password = config.password;
    ua.local_address = local->address_string();
    ua.local_port = local->port;
    ua.register_expires = config.register_expires != 0 ? config.register_expires : 300;
    ua.user_agent = or_default(config.user_agent, std::string("KetPhone/") + KETPHONE_VERSION);
    ua.correlation_header = or_default(config.correlation_header, {});

    const uint32_t jitter_ms = config.jitter_buffer_ms != 0 ? config.jitter_buffer_ms : 60;

    auto engine = std::unique_ptr<Engine>(new Engine(std::move(ua), std::move(*sip), int64_t{jitter_ms} * 1000, callback, context));
    if (!engine->start()) return nullptr;
    return engine;
  }

  ~Engine() override {
    stop();
    if (wake_[0] >= 0) ::close(wake_[0]);
    if (wake_[1] >= 0) ::close(wake_[1]);
  }

  Engine(const Engine&) = delete;
  Engine& operator=(const Engine&) = delete;

  // Runs `command` on the network thread and returns its result. Called on the network thread
  // itself (from the event callback), it runs inline: the user agent is never mid-operation
  // while events are being delivered.
  ketphone_result run(std::function<ketphone_result()> command) {
    if (std::this_thread::get_id() == thread_id_) return command();
    std::promise<ketphone_result> promise;
    auto future = promise.get_future();
    {
      std::lock_guard lock(queue_mutex_);
      if (closed_) return KETPHONE_ERROR_STATE;
      queue_.emplace_back([&promise, &command](bool run) {
        promise.set_value(run ? command() : KETPHONE_ERROR_STATE);
      });
    }
    wake();
    return future.get();
  }

  ketphone_result register_account() {
    return run([this] {
      ua_.start_registration(Clock::now());
      return KETPHONE_OK;
    });
  }

  ketphone_result unregister_account() {
    return run([this] {
      ua_.stop_registration(Clock::now());
      return KETPHONE_OK;
    });
  }

  ketphone_result call(const std::string& target, ketphone_call_id* call_id) {
    const int32_t id = next_call_id_.fetch_add(1);
    const ketphone_result result = run([this, &target, id] { return to_result(ua_.call(id, target, Clock::now())); });
    if (result == KETPHONE_OK && call_id != nullptr) *call_id = id;
    return result;
  }

  ketphone_result answer(ketphone_call_id id) {
    return run([this, id] { return to_result(ua_.answer(id, Clock::now())); });
  }

  ketphone_result reject(ketphone_call_id id, int32_t status) {
    return run([this, id, status] { return to_result(ua_.reject(id, status, Clock::now())); });
  }

  ketphone_result hangup(ketphone_call_id id) {
    return run([this, id] { return to_result(ua_.hangup(id, Clock::now())); });
  }

  size_t capture(const int16_t* samples, size_t count) { return capture_.push(samples, count); }

  size_t playout(int16_t* samples, size_t count) {
    const size_t real = playout_.pop(samples, count);
    std::fill(samples + real, samples + count, int16_t{0});
    return real;
  }

  ketphone_media_stats stats() {
    std::lock_guard lock(stats_mutex_);
    ketphone_media_stats out{};
    out.packets_sent = stats_.packets_sent;
    out.packets_received = stats_.packets_received;
    out.packets_lost = stats_.packets_lost;
    out.packets_late = stats_.packets_late;
    out.frames_concealed = stats_.frames_concealed;
    out.jitter_ms = stats_.jitter_ms;
    out.frames_expanded = stats_.frames_expanded;
    out.frames_dropped = stats_.frames_dropped;
    out.playout_delay_ms = stats_.playout_delay_ms;
    return out;
  }

  // UserAgentHost, on the network thread.

  void send_sip(const std::string& message) override {
    sip_.send({reinterpret_cast<const uint8_t*>(message.data()), message.size()});
  }

  uint16_t open_media() override {
    rtp_ = net::UdpSocket::open();
    if (!rtp_) return 0;
    const auto local = rtp_->local();
    if (!local) {
      rtp_.reset();
      return 0;
    }
    return local->port;
  }

  void start_media(const RemoteMedia& remote) override {
    const auto endpoint = net::resolve(remote.address, remote.port);
    if (!endpoint || !rtp_) return;
    rtp_remote_ = *endpoint;
    if (media_.active()) return;  // a re-INVITE only moves the far end
    media_.start(sip::random_u32(), static_cast<uint16_t>(sip::random_u32()), sip::random_u32());
    next_frame_ = Clock::now();
  }

  void close_media() override {
    if (media_.active()) publish_stats();
    media_.stop();
    rtp_.reset();
  }

 private:
  Engine(UserAgentConfig config, net::UdpSocket sip, int64_t initial_delay_us, ketphone_event_callback callback,
         void* context)
      : sip_(std::move(sip)),
        capture_(kRingSamples),
        playout_(kRingSamples),
        media_(capture_, playout_, initial_delay_us),
        ua_(std::move(config), *this),
        callback_(callback),
        context_(context) {
    ua_.allocate_call_id = [this] { return next_call_id_.fetch_add(1); };
  }

  bool start() {
    if (::pipe(wake_) != 0) return false;
    for (const int fd : wake_) {
      fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK);
      fcntl(fd, F_SETFD, FD_CLOEXEC);
    }
    std::promise<void> started;
    auto ready = started.get_future();
    thread_ = std::thread([this, &started] {
      thread_id_ = std::this_thread::get_id();
      started.set_value();
      loop();
    });
    ready.wait();
    return true;
  }

  void stop() {
    if (!thread_.joinable()) return;
    {
      std::lock_guard lock(queue_mutex_);
      if (!closed_) {
        queue_.emplace_back([this](bool) {
          ua_.shutdown(Clock::now());
          stopping_ = true;
          stop_deadline_ = Clock::now() + kShutdownGrace;
        });
      }
    }
    wake();
    thread_.join();
  }

  void wake() {
    const uint8_t byte = 1;
    [[maybe_unused]] const auto written = ::write(wake_[1], &byte, 1);
  }

  void deliver_events() {
    for (;;) {
      auto events = ua_.take_events();
      if (events.empty()) return;
      for (const auto& event : events) {
        if (callback_ == nullptr) continue;
        ketphone_event out{};
        out.kind = static_cast<ketphone_event_kind>(event.kind);
        out.call_id = event.call_id;
        out.status_code = event.status;
        out.end_reason = to_c(event.end_reason);
        out.remote = event.remote.c_str();
        out.remote_display_name = event.remote_display_name.c_str();
        out.correlation_id = event.correlation_id.c_str();
        callback_(&out, context_);
      }
    }
  }

  void run_commands() {
    std::deque<std::function<void(bool)>> commands;
    {
      std::lock_guard lock(queue_mutex_);
      commands.swap(queue_);
    }
    for (auto& command : commands) {
      command(true);
      deliver_events();
    }
  }

  void publish_stats() {
    std::lock_guard lock(stats_mutex_);
    stats_ = media_.stats();
  }

  void loop() {
    std::array<uint8_t, 65536> buffer{};
    for (;;) {
      TimePoint now = Clock::now();
      TimePoint wake_at = now + 200ms;
      if (const auto deadline = ua_.next_deadline()) wake_at = std::min(wake_at, *deadline);
      if (media_.active()) wake_at = std::min(wake_at, next_frame_);
      if (stopping_) wake_at = std::min(wake_at, stop_deadline_);
      const auto timeout = std::chrono::duration_cast<std::chrono::milliseconds>(wake_at - now).count();

      std::array<pollfd, 3> fds{};
      fds[0] = {wake_[0], POLLIN, 0};
      fds[1] = {sip_.fd(), POLLIN, 0};
      nfds_t count = 2;
      if (rtp_) fds[count++] = {rtp_->fd(), POLLIN, 0};
      ::poll(fds.data(), count, static_cast<int>(std::max<long long>(0, timeout)));

      while (::read(wake_[0], buffer.data(), buffer.size()) > 0) {
      }
      run_commands();

      for (;;) {
        const auto size = sip_.receive(buffer);
        if (!size || *size == 0) break;  // an ICMP error on the connected socket also lands here
        ua_.on_message({reinterpret_cast<const char*>(buffer.data()), *size}, Clock::now());
        deliver_events();
      }

      while (rtp_ && media_.active()) {
        const auto size = rtp_->receive(buffer);
        if (!size || *size == 0) break;
        media_.on_packet({buffer.data(), *size}, micros(Clock::now()));
      }

      now = Clock::now();
      ua_.on_timer(now);
      deliver_events();

      if (media_.active() && rtp_ && now >= next_frame_) {
        // Catch up after a stall, but never burst more than a few frames.
        if (now - next_frame_ > 10 * kFrame) next_frame_ = now;
        while (now >= next_frame_) {
          std::array<uint8_t, media::kMaxPacketSize> packet{};
          const size_t size = media_.next_packet(packet);
          if (size > 0) rtp_->send_to({packet.data(), size}, rtp_remote_);
          media_.play_frame(micros(next_frame_));
          next_frame_ += kFrame;
        }
        publish_stats();
      }

      if (stopping_ && (ua_.idle() || Clock::now() >= stop_deadline_)) break;
    }

    std::deque<std::function<void(bool)>> abandoned;
    {
      std::lock_guard lock(queue_mutex_);
      closed_ = true;
      abandoned.swap(queue_);
    }
    for (auto& command : abandoned) command(false);
  }

  net::UdpSocket sip_;
  std::optional<net::UdpSocket> rtp_;
  net::Endpoint rtp_remote_;
  media::SpscRing<int16_t> capture_;
  media::SpscRing<int16_t> playout_;
  media::MediaSession media_;
  UserAgent ua_;
  ketphone_event_callback callback_;
  void* context_;

  std::atomic<int32_t> next_call_id_{1};
  TimePoint next_frame_{};

  std::thread thread_;
  std::thread::id thread_id_;
  int wake_[2] = {-1, -1};
  std::mutex queue_mutex_;
  std::deque<std::function<void(bool)>> queue_;
  bool closed_ = false;
  bool stopping_ = false;
  TimePoint stop_deadline_{};

  std::mutex stats_mutex_;
  media::MediaStats stats_;
};

}  // namespace ketphone::core

struct ketphone_engine {
  std::unique_ptr<ketphone::core::Engine> engine;
};

extern "C" {

const char* ketphone_version(void) { return KETPHONE_VERSION; }

ketphone_engine* ketphone_engine_create(const ketphone_config* config, ketphone_event_callback callback,
                                        void* context) {
  if (config == nullptr || config->struct_size < sizeof(ketphone_config)) return nullptr;
  try {
    auto engine = ketphone::core::Engine::create(*config, callback, context);
    if (!engine) return nullptr;
    return new ketphone_engine{std::move(engine)};
  } catch (...) {
    return nullptr;
  }
}

void ketphone_engine_destroy(ketphone_engine* engine) { delete engine; }

#define KETPHONE_GUARD(expression)                 \
  do {                                             \
    if (engine == nullptr) return KETPHONE_ERROR_INVALID_ARGUMENT; \
    try {                                          \
      return (expression);                         \
    } catch (...) {                                \
      return KETPHONE_ERROR_INTERNAL;              \
    }                                              \
  } while (false)

ketphone_result ketphone_register(ketphone_engine* engine) { KETPHONE_GUARD(engine->engine->register_account()); }

ketphone_result ketphone_unregister(ketphone_engine* engine) {
  KETPHONE_GUARD(engine->engine->unregister_account());
}

ketphone_result ketphone_call(ketphone_engine* engine, const char* target, ketphone_call_id* call_id) {
  if (target == nullptr) return KETPHONE_ERROR_INVALID_ARGUMENT;
  KETPHONE_GUARD(engine->engine->call(target, call_id));
}

ketphone_result ketphone_answer(ketphone_engine* engine, ketphone_call_id call_id) {
  KETPHONE_GUARD(engine->engine->answer(call_id));
}

ketphone_result ketphone_reject(ketphone_engine* engine, ketphone_call_id call_id, int32_t status_code) {
  KETPHONE_GUARD(engine->engine->reject(call_id, status_code));
}

ketphone_result ketphone_hangup(ketphone_engine* engine, ketphone_call_id call_id) {
  KETPHONE_GUARD(engine->engine->hangup(call_id));
}

size_t ketphone_audio_capture(ketphone_engine* engine, const int16_t* samples, size_t count) {
  if (engine == nullptr || samples == nullptr) return 0;
  return engine->engine->capture(samples, count);
}

size_t ketphone_audio_playout(ketphone_engine* engine, int16_t* samples, size_t count) {
  if (engine == nullptr || samples == nullptr) return 0;
  return engine->engine->playout(samples, count);
}

ketphone_result ketphone_media_stats_get(ketphone_engine* engine, ketphone_media_stats* stats) {
  if (stats == nullptr) return KETPHONE_ERROR_INVALID_ARGUMENT;
  KETPHONE_GUARD((*stats = engine->engine->stats(), KETPHONE_OK));
}

}  // extern "C"
