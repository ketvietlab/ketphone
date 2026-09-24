// ketphone-poc: drives the KetPhone core through its C API only, the way the apps will.
//
//   KETPHONE_PASSWORD=... ketphone-poc --server 127.0.0.1 --user 1001 --call '*43'
//     Registers, calls the echo test, plays tone bursts for a few seconds, measures how long each
//     burst takes to come back and prints media statistics.
//
//   KETPHONE_PASSWORD=... ketphone-poc --server 127.0.0.1 --user 1002 --answer
//     Registers, answers the first incoming call and loops received audio back, so a second
//     instance calling this extension measures the round trip through the server.
//
// The password comes from the environment so it never shows up in the process list.
#include <algorithm>
#include <atomic>
#include <chrono>
#include <cmath>
#include <condition_variable>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <vector>

#include "ketphone/ketphone.h"

namespace {

using Clock = std::chrono::steady_clock;
using namespace std::chrono_literals;

constexpr int kRate = KETPHONE_SAMPLE_RATE;
constexpr size_t kFrame = 160;
// Test signal: a 60 ms 1 kHz burst every 500 ms.
constexpr int kBurstPeriod = kRate / 2;
constexpr int kBurstLength = kRate * 60 / 1000;
constexpr int kBurstAmplitude = 10000;
// A received burst starts where the level first crosses this after at least 200 ms of quiet.
constexpr int kDetectThreshold = 2500;
constexpr int kQuietBeforeOnset = kRate / 5;

struct Options {
  std::string server = "127.0.0.1";
  uint16_t port = 5060;
  std::string user;
  std::string call;
  bool answer = false;
  int seconds = 10;
  unsigned jitter_ms = 60;
  std::string correlation_header = "X-KV-Call-Id";
};

struct Event {
  ketphone_event_kind kind;
  ketphone_call_id call_id;
  int status;
  ketphone_end_reason reason;
  std::string remote;
  std::string correlation_id;
};

class EventQueue {
 public:
  void push(Event event) {
    {
      std::lock_guard lock(mutex_);
      events_.push_back(std::move(event));
    }
    ready_.notify_all();
  }

  std::optional<Event> wait(Clock::time_point until) {
    std::unique_lock lock(mutex_);
    if (!ready_.wait_until(lock, until, [this] { return !events_.empty(); })) return std::nullopt;
    Event event = std::move(events_.front());
    events_.pop_front();
    return event;
  }

 private:
  std::mutex mutex_;
  std::condition_variable ready_;
  std::deque<Event> events_;
};

std::atomic<bool> interrupted{false};

const char* reason_name(ketphone_end_reason reason) {
  switch (reason) {
    case KETPHONE_END_LOCAL: return "local";
    case KETPHONE_END_REMOTE_HANGUP: return "remote-hangup";
    case KETPHONE_END_REMOTE_CANCELLED: return "remote-cancelled";
    case KETPHONE_END_REJECTED: return "rejected";
    case KETPHONE_END_TIMEOUT: return "timeout";
    case KETPHONE_END_MEDIA_FAILED: return "media-failed";
    case KETPHONE_END_SHUTDOWN: return "shutdown";
    default: return "none";
  }
}

void on_event(const ketphone_event* event, void* context) {
  static_cast<EventQueue*>(context)->push(Event{event->kind, event->call_id, event->status_code, event->end_reason,
                                                event->remote, event->correlation_id});
}

double millis_since(Clock::time_point start) {
  return std::chrono::duration<double, std::milli>(Clock::now() - start).count();
}

void usage() {
  std::fprintf(stderr,
               "usage: KETPHONE_PASSWORD=... ketphone-poc --user EXT (--call TARGET | --answer)\n"
               "         [--server HOST[:PORT]] [--seconds N] [--jitter-ms N] [--correlation-header NAME]\n");
}

std::optional<Options> parse_options(int argc, char** argv) {
  Options options;
  for (int i = 1; i < argc; ++i) {
    const std::string arg = argv[i];
    const auto value = [&]() -> std::optional<std::string> {
      if (i + 1 >= argc) return std::nullopt;
      return std::string(argv[++i]);
    };
    if (arg == "--answer") {
      options.answer = true;
      continue;
    }
    const auto next = value();
    if (!next) return std::nullopt;
    if (arg == "--server") {
      const size_t colon = next->find(':');
      options.server = next->substr(0, colon);
      if (colon != std::string::npos) options.port = static_cast<uint16_t>(std::atoi(next->c_str() + colon + 1));
    } else if (arg == "--user") {
      options.user = *next;
    } else if (arg == "--call") {
      options.call = *next;
    } else if (arg == "--seconds") {
      options.seconds = std::max(1, std::atoi(next->c_str()));
    } else if (arg == "--jitter-ms") {
      options.jitter_ms = static_cast<unsigned>(std::max(20, std::atoi(next->c_str())));
    } else if (arg == "--correlation-header") {
      options.correlation_header = *next;
    } else {
      return std::nullopt;
    }
  }
  if (options.user.empty() || options.call.empty() == !options.answer) return std::nullopt;
  return options;
}

// Simulated audio device: every 20 ms it hands the engine one frame of microphone audio and takes
// one frame to play, like a hardware callback would. In measure mode the microphone plays tone
// bursts and the speaker side looks for them; in loopback mode the speaker feeds the microphone.
class AudioDevice {
 public:
  AudioDevice(ketphone_engine* engine, bool loopback) : engine_(engine), loopback_(loopback) {}

  void start() {
    thread_ = std::thread([this] { run(); });
  }

  void stop() {
    running_ = false;
    if (thread_.joinable()) thread_.join();
  }

  // Round-trip delay of each burst that came back, in milliseconds.
  std::vector<double> delays() const { return delays_; }
  size_t bursts_sent() const { return sent_onsets_.size(); }

 private:
  void run() {
    std::vector<int16_t> microphone(kFrame);
    std::vector<int16_t> speaker(kFrame);
    auto next = Clock::now();
    while (running_) {
      ketphone_audio_playout(engine_, speaker.data(), speaker.size());
      if (loopback_) {
        microphone = speaker;
      } else {
        for (size_t i = 0; i < kFrame; ++i) microphone[i] = tone(sample_ + static_cast<int64_t>(i));
        detect(speaker);
      }
      ketphone_audio_capture(engine_, microphone.data(), microphone.size());
      sample_ += kFrame;
      next += 20ms;
      std::this_thread::sleep_until(next);
    }
  }

  int16_t tone(int64_t sample) {
    const int64_t phase = sample % kBurstPeriod;
    if (phase == 0) sent_onsets_.push_back(sample);
    if (phase >= kBurstLength) return 0;
    const double value = kBurstAmplitude * std::sin(2.0 * M_PI * 1000.0 * static_cast<double>(phase) / kRate);
    return static_cast<int16_t>(value);
  }

  void detect(const std::vector<int16_t>& frame) {
    for (size_t i = 0; i < frame.size(); ++i) {
      const int64_t at = sample_ + static_cast<int64_t>(i);
      if (std::abs(frame[i]) < kDetectThreshold) continue;
      if (at - last_loud_ >= kQuietBeforeOnset) {
        // Match the onset to the most recent burst sent before it.
        const auto sent = std::upper_bound(sent_onsets_.begin(), sent_onsets_.end(), at);
        if (sent != sent_onsets_.begin()) {
          const int64_t delay = at - *std::prev(sent);
          delays_.push_back(static_cast<double>(delay) * 1000.0 / kRate);
        }
      }
      last_loud_ = at;
    }
  }

  ketphone_engine* engine_;
  bool loopback_;
  std::atomic<bool> running_{true};
  std::thread thread_;
  int64_t sample_ = 0;
  int64_t last_loud_ = -kRate;
  std::vector<int64_t> sent_onsets_;
  std::vector<double> delays_;
};

bool wait_registered(EventQueue& events, Clock::time_point start) {
  while (const auto event = events.wait(Clock::now() + 10s)) {
    if (event->kind != KETPHONE_EVENT_REGISTRATION) continue;
    std::printf("register status=%d ms=%.0f\n", event->status, millis_since(start));
    return event->status == 200;
  }
  std::printf("register status=timeout\n");
  return false;
}

void print_stats(ketphone_engine* engine) {
  ketphone_media_stats stats{};
  ketphone_media_stats_get(engine, &stats);
  std::printf(
      "media sent=%llu received=%llu lost=%llu late=%llu concealed=%llu expanded=%llu dropped=%llu jitter_ms=%.2f "
      "playout_delay_ms=%.1f\n",
              static_cast<unsigned long long>(stats.packets_sent),
              static_cast<unsigned long long>(stats.packets_received),
              static_cast<unsigned long long>(stats.packets_lost), static_cast<unsigned long long>(stats.packets_late),
              static_cast<unsigned long long>(stats.frames_concealed),
              static_cast<unsigned long long>(stats.frames_expanded),
              static_cast<unsigned long long>(stats.frames_dropped), stats.jitter_ms, stats.playout_delay_ms);
}

// Runs media until the deadline or until the call ends; returns true when the far end hung up.
bool hold_call(EventQueue& events, Clock::time_point until) {
  while (Clock::now() < until && !interrupted) {
    const auto event = events.wait(std::min(until, Clock::now() + 200ms));
    if (event && event->kind == KETPHONE_EVENT_CALL_ENDED) {
      std::printf("ended reason=%s status=%d\n", reason_name(event->reason), event->status);
      return true;
    }
  }
  return false;
}

void hang_up(ketphone_engine* engine, EventQueue& events, ketphone_call_id id) {
  ketphone_hangup(engine, id);
  while (const auto event = events.wait(Clock::now() + 5s)) {
    if (event->kind == KETPHONE_EVENT_CALL_ENDED) {
      std::printf("ended reason=%s status=%d\n", reason_name(event->reason), event->status);
      return;
    }
  }
}

int run_caller(ketphone_engine* engine, EventQueue& events, const Options& options) {
  const auto start = Clock::now();
  ketphone_call_id id = 0;
  if (ketphone_call(engine, options.call.c_str(), &id) != KETPHONE_OK) {
    std::printf("call error=could-not-start\n");
    return 1;
  }
  bool answered = false;
  while (!answered && !interrupted) {
    const auto event = events.wait(Clock::now() + 60s);
    if (!event) {
      std::printf("call error=no-answer-within-60s\n");
      hang_up(engine, events, id);
      return 1;
    }
    if (event->call_id != id) continue;
    if (event->kind == KETPHONE_EVENT_CALL_PROGRESS) {
      std::printf("progress status=%d ms=%.0f\n", event->status, millis_since(start));
    } else if (event->kind == KETPHONE_EVENT_CALL_ANSWERED) {
      std::printf("answered ms=%.0f remote=%s\n", millis_since(start), event->remote.c_str());
      answered = true;
    } else if (event->kind == KETPHONE_EVENT_CALL_ENDED) {
      std::printf("ended reason=%s status=%d ms=%.0f\n", reason_name(event->reason), event->status,
                  millis_since(start));
      return 1;
    }
  }
  if (!answered) {
    hang_up(engine, events, id);
    return 1;
  }

  AudioDevice device(engine, false);
  device.start();
  const bool remote_ended = hold_call(events, Clock::now() + std::chrono::seconds(options.seconds));
  device.stop();
  print_stats(engine);
  if (!remote_ended) hang_up(engine, events, id);

  auto delays = device.delays();
  const size_t sent = device.bursts_sent();
  std::sort(delays.begin(), delays.end());
  if (delays.empty()) {
    std::printf("echo sent=%zu returned=0\n", sent);
    return 1;
  }
  std::printf("echo sent=%zu returned=%zu delay_ms min=%.1f median=%.1f max=%.1f\n", sent, delays.size(),
              delays.front(), delays[delays.size() / 2], delays.back());
  // The last burst may still have been on its way back when the call ended.
  return delays.size() * 5 >= (sent > 0 ? sent - 1 : 0) * 4 ? 0 : 1;
}

int run_answerer(ketphone_engine* engine, EventQueue& events, const Options& options) {
  std::printf("waiting for a call to %s\n", options.user.c_str());
  const auto give_up = Clock::now() + std::chrono::seconds(std::max(options.seconds, 60));
  std::optional<ketphone_call_id> id;
  while (!id && !interrupted) {
    const auto event = events.wait(give_up);
    if (!event) {
      std::printf("incoming error=none-within-wait\n");
      return 1;
    }
    if (event->kind == KETPHONE_EVENT_CALL_INCOMING) {
      std::printf("incoming from=%s correlation=%s\n", event->remote.c_str(), event->correlation_id.c_str());
      id = event->call_id;
    }
  }
  if (!id) return 1;
  std::this_thread::sleep_for(500ms);
  if (ketphone_answer(engine, *id) != KETPHONE_OK) {
    std::printf("answer error=rejected-by-engine\n");
    return 1;
  }
  AudioDevice device(engine, true);
  device.start();
  const bool remote_ended = hold_call(events, Clock::now() + std::chrono::seconds(options.seconds + 30));
  device.stop();
  print_stats(engine);
  if (!remote_ended) hang_up(engine, events, *id);
  return 0;
}

}  // namespace

int main(int argc, char** argv) {
  // Other tools watch this output line by line (e.g. to start calling once the answerer is ready).
  std::setvbuf(stdout, nullptr, _IOLBF, 0);
  const auto options = parse_options(argc, argv);
  const char* password = std::getenv("KETPHONE_PASSWORD");
  if (!options || password == nullptr || password[0] == '\0') {
    usage();
    return 2;
  }
  std::signal(SIGINT, [](int) { interrupted = true; });
  std::signal(SIGTERM, [](int) { interrupted = true; });

  EventQueue events;
  ketphone_config config{};
  config.struct_size = sizeof(config);
  config.server_host = options->server.c_str();
  config.server_port = options->port;
  config.extension = options->user.c_str();
  config.password = password;
  config.register_expires = 120;
  config.jitter_buffer_ms = options->jitter_ms;
  config.user_agent = "ketphone-poc";
  config.correlation_header = options->correlation_header.c_str();

  std::printf("ketphone %s server=%s:%u user=%s\n", ketphone_version(), options->server.c_str(), options->port,
              options->user.c_str());
  ketphone_engine* engine = ketphone_engine_create(&config, on_event, &events);
  if (engine == nullptr) {
    std::printf("engine error=create-failed\n");
    return 1;
  }

  int code = 1;
  const auto start = Clock::now();
  ketphone_register(engine);
  if (wait_registered(events, start)) {
    code = options->answer ? run_answerer(engine, events, *options) : run_caller(engine, events, *options);
  }
  ketphone_engine_destroy(engine);
  std::printf("exit code=%d\n", code);
  return code;
}
