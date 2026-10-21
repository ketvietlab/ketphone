#pragma once

#include <chrono>
#include <cstdint>
#include <functional>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "sip/message.hpp"
#include "sip/sdp.hpp"

namespace ketphone::core {

using Clock = std::chrono::steady_clock;
using TimePoint = Clock::time_point;
using Duration = Clock::duration;

struct UserAgentConfig {
  // SIP domain and request target, e.g. the server's IP address.
  std::string domain;
  std::string extension;
  std::string password;
  // Where the server can reach this side; used in Via, Contact and SDP. A port of 0 is left out of
  // Via and Contact, as over TLS, where the server answers on the connection the request came on.
  std::string local_address;
  uint16_t local_port = 0;
  // Signalling transport named in Via and Contact: "UDP" or "TLS". Requests over TLS are not
  // retransmitted (RFC 3261 section 17.1.1.2); the connection is reliable.
  std::string transport = "UDP";
  // Media must be SRTP with SDES keys: offers carry this side's key, and an offer or answer without
  // a usable AES_CM_128_HMAC_SHA1_80 key is refused (488). Only meaningful over TLS, since the keys
  // travel in the SIP messages.
  bool srtp = false;
  uint32_t register_expires = 300;
  std::string user_agent;
  // Header on incoming INVITEs whose value is reported as the event's correlation_id; empty
  // disables it.
  std::string correlation_header;
};

enum class EventKind { Registration = 1, CallIncoming, CallProgress, CallAnswered, CallEnded };

enum class EndReason { None, Local, RemoteHangup, RemoteCancelled, Rejected, Timeout, MediaFailed, Shutdown };

struct Event {
  EventKind kind = EventKind::Registration;
  int32_t call_id = 0;
  int32_t status = 0;
  EndReason end_reason = EndReason::None;
  std::string remote;
  std::string remote_display_name;
  std::string correlation_id;
};

// SRTP master keys and salts of one call, as exchanged in SDES crypto lines.
struct MediaKeys {
  std::vector<uint8_t> local;   // what this side encrypts with
  std::vector<uint8_t> remote;  // what the far end encrypts with
};

struct RemoteMedia {
  std::string address;
  uint16_t port = 0;
  // Set when the call's media is SRTP.
  std::optional<MediaKeys> srtp;
};

// What the user agent needs from its surroundings. The engine implements it with sockets; tests
// implement it with vectors.
class UserAgentHost {
 public:
  virtual ~UserAgentHost() = default;
  // Sends a datagram to the SIP server; every request and response goes there.
  virtual void send_sip(const std::string& message) = 0;
  // Opens the RTP socket for the call and returns its local port, or 0 on failure.
  virtual uint16_t open_media() = 0;
  // Starts (or redirects) media towards the far end. Called at most after open_media. Returns false
  // when the media cannot be secured as negotiated (SRTP keys refused); the call then ends.
  virtual bool start_media(const RemoteMedia& remote) = 0;
  virtual void close_media() = 0;
};

enum class CommandResult { Ok, InvalidArgument, State, NotFound };

// SIP user agent for one account and at most one call, as a single-threaded state machine. It
// never blocks and never reads the clock: callers pass `now` and call on_timer by
// next_deadline(). Events are queued and collected with take_events, so a caller reacting to an
// event can issue the next command without re-entering the user agent.
class UserAgent {
 public:
  UserAgent(UserAgentConfig config, UserAgentHost& host);

  void on_message(std::string_view datagram, TimePoint now);
  void on_timer(TimePoint now);
  std::optional<TimePoint> next_deadline() const;
  std::vector<Event> take_events();

  void start_registration(TimePoint now);
  void stop_registration(TimePoint now);
  CommandResult call(int32_t call_id, const std::string& target, TimePoint now);
  CommandResult answer(int32_t call_id, TimePoint now);
  CommandResult reject(int32_t call_id, int32_t status, TimePoint now);
  CommandResult hangup(int32_t call_id, TimePoint now);

  // Ends the call and unregisters. Afterwards wait for idle() before dropping the transport.
  void shutdown(TimePoint now);

  // A connection-oriented transport closed. Requests in flight went with it and fail as if they
  // had timed out; a registration that was in place is reported lost (503). A connected call keeps
  // its media.
  void on_transport_down(TimePoint now);
  // A new connection is up: registers again when registration is wanted and none is in flight.
  void on_transport_up(TimePoint now);
  bool idle() const { return transactions_.empty(); }

  bool registered() const { return registration_.registered; }
  bool has_call() const { return call_.has_value(); }

  // Incoming calls need ids too; the engine shares its counter so ids never collide.
  std::function<int32_t()> allocate_call_id;

 private:
  using FinalHandler = std::function<void(const sip::Message* response, TimePoint now)>;
  using ProvisionalHandler = std::function<void(const sip::Message& response, TimePoint now)>;

  struct Transaction {
    std::string method;
    std::string bytes;
    bool retransmitting = true;
    Duration interval{};
    TimePoint retransmit_at{};
    TimePoint deadline{};
    ProvisionalHandler on_provisional;
    FinalHandler on_final;
  };

  struct Request {
    std::string method;
    std::string uri;
    std::string from;
    std::string to;
    std::string call_id;
    uint32_t cseq = 0;
    std::vector<std::pair<std::string, std::string>> extra;
    std::string body;
  };

  // What the INVITE transaction needs to finish itself even after the call is gone.
  struct InviteContext {
    int32_t call_id = 0;
    std::string uri;
    std::string from;
    std::string sip_call_id;
    uint32_t cseq = 0;
    std::string branch;
  };

  enum class CallState { Calling, Ringing, Answering, Confirmed };

  struct Call {
    int32_t id = 0;
    bool outgoing = false;
    CallState state = CallState::Calling;
    std::string sip_call_id;
    std::string local_tag;
    // From and To of requests this side sends inside the dialog.
    std::string local_header;
    std::string remote_header;
    std::string remote_target;
    std::string remote_uri;
    std::string remote_display_name;
    uint32_t local_cseq = 0;
    bool media_open = false;
    std::string local_sdp;
    uint16_t media_port = 0;
    uint64_t sdp_session = 0;
    uint64_t sdp_version = 1;
    // This side's SRTP key for the call, when the call is secure.
    std::vector<uint8_t> srtp_key;

    // Outgoing.
    std::string invite_uri;
    std::string invite_branch;
    uint32_t invite_cseq = 0;
    bool authenticated = false;
    bool provisional = false;
    int32_t last_progress = 0;
    bool cancel_requested = false;
    bool cancel_sent = false;
    std::string ack;

    // Incoming.
    std::optional<sip::Message> invite;
    sip::AudioDescription offer;
    std::string last_response;
    Duration resend_interval{};
    TimePoint resend_at{};
    TimePoint ack_deadline{};
    std::string correlation_id;
  };

  struct Registration {
    bool wanted = false;
    bool registered = false;
    bool in_flight = false;
    std::string call_id;
    std::string from_tag;
    uint32_t cseq = 0;
    std::optional<TimePoint> next_attempt;
  };

  std::string aor() const;
  std::string contact() const;
  std::string via(const std::string& branch) const;
  bool reliable() const { return config_.transport != "UDP"; }
  std::string sent_by() const;

  // Whether a far end's offer (or answer) suits this side: PCMA, and with SRTP a usable key. The
  // chosen key is returned through `key` when SRTP is on.
  bool acceptable(const sip::AudioDescription& media, const sip::SdesCrypto** key) const;
  // This side's SDP for the call; `answering` is the offer it answers, if any.
  std::string local_sdp_for(Call& call, const sip::AudioDescription* answering) const;
  RemoteMedia remote_media_for(const Call& call, const sip::AudioDescription& media,
                               const sip::SdesCrypto* key) const;
  // Draws this side's SRTP key for the call when SRTP is on; false if the system generator failed.
  bool new_srtp_key(Call& call) const;
  std::string build_request(const Request& request, const std::string& branch) const;
  std::string send_request(const Request& request, TimePoint now, FinalHandler on_final,
                           ProvisionalHandler on_provisional = {}, std::string branch = {});
  void send_raw(const std::string& message);
  std::string build_response(const sip::Message& request, int32_t status, const std::string& to_tag,
                             const std::string& body = {}) const;

  void send_register(uint32_t expires, const std::string& authorization, TimePoint now);
  void on_register_final(const sip::Message* response, uint32_t expires, bool authenticated, TimePoint now);

  void send_invite(const std::string& authorization, TimePoint now);
  void on_invite_provisional(int32_t call_id, const sip::Message& response, TimePoint now);
  void on_invite_final(const InviteContext& context, const sip::Message* response, TimePoint now);
  void send_ack_for_failure(const InviteContext& context, const sip::Message& response);
  void send_cancel(TimePoint now);
  void send_bye(TimePoint now);

  void on_request(const sip::Message& request, TimePoint now);
  void on_response(const sip::Message& response, TimePoint now);
  void on_invite_request(const sip::Message& request, TimePoint now);

  void end_call(EndReason reason, int32_t status);
  void emit(Event event);
  std::optional<std::string> authorization_for(const sip::Message& challenge, const std::string& method,
                                               const std::string& uri) const;

  UserAgentConfig config_;
  UserAgentHost& host_;
  std::map<std::string, Transaction> transactions_;
  Registration registration_;
  std::optional<Call> call_;
  std::vector<Event> events_;
  bool shutting_down_ = false;
};

}  // namespace ketphone::core
