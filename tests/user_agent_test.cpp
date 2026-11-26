// The user agent against a scripted server: every datagram it sends is parsed and answered the
// way the Asterisk configuration in ketviet's infra/telephony answers it.
#include <algorithm>
#include <chrono>
#include <string>
#include <vector>

#include "check.hpp"
#include "core/user_agent.hpp"
#include "sip/digest.hpp"
#include "sip/message.hpp"
#include "sip/sdp.hpp"

using namespace ketphone;
using namespace ketphone::core;
using namespace std::chrono_literals;

namespace {

class FakeHost : public UserAgentHost {
 public:
  void send_sip(const std::string& message) override { sent.push_back(message); }
  uint16_t open_media() override {
    ++media_opened;
    return media_port;
  }
  bool start_media(const RemoteMedia& remote) override {
    media.push_back(remote);
    return accept_media;
  }
  void close_media() override { ++media_closed; }
  bool send_dtmf(std::string_view keys, uint32_t duration_ms) override {
    dtmf.emplace_back(std::string(keys), duration_ms);
    return true;
  }
  void start_ringback() override { ++ringback_started; }
  void stop_ringback() override { ++ringback_stopped; }

  sip::Message last() const { return *sip::parse_message(sent.back()); }
  sip::Message at(size_t index) const { return *sip::parse_message(sent.at(index)); }

  std::vector<std::string> sent;
  std::vector<RemoteMedia> media;
  std::vector<std::pair<std::string, uint32_t>> dtmf;
  uint16_t media_port = 40000;
  bool accept_media = true;
  int media_opened = 0;
  int media_closed = 0;
  int ringback_started = 0;
  int ringback_stopped = 0;
  bool ringing() const { return ringback_started > ringback_stopped; }
};

UserAgentConfig config() {
  UserAgentConfig out;
  out.domain = "127.0.0.1";
  out.extension = "1001";
  out.password = "secret";
  out.local_address = "192.168.1.20";
  out.local_port = 50000;
  out.register_expires = 120;
  out.user_agent = "test";
  out.correlation_header = "X-KV-Call-Id";
  return out;
}

// A response to `request` as the server would send it.
std::string respond(const sip::Message& request, int status, const std::string& extra = {},
                    const std::string& to_tag = "srv", const std::string& body = {}) {
  std::string to(*request.header("to"));
  if (!to_tag.empty() && to.find(";tag=") == std::string::npos) to += ";tag=" + to_tag;
  std::string out = "SIP/2.0 " + std::to_string(status) + " X\r\n";
  for (const auto via : request.header_all("via")) out += "Via: " + std::string(via) + "\r\n";
  out += "From: " + std::string(*request.header("from")) + "\r\n";
  out += "To: " + to + "\r\n";
  out += "Call-ID: " + std::string(*request.header("call-id")) + "\r\n";
  out += "CSeq: " + std::string(*request.header("cseq")) + "\r\n";
  out += extra;
  if (!body.empty()) out += "Content-Type: application/sdp\r\n";
  out += "Content-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;
  return out;
}

const std::string kChallenge =
    "WWW-Authenticate: Digest realm=\"ketviet\",nonce=\"n-1\",opaque=\"o\",algorithm=MD5,qop=\"auth\"\r\n";
const std::string kProxyChallenge = "Proxy-Authenticate: Digest realm=\"ketviet\",nonce=\"n-2\",algorithm=MD5\r\n";
const std::string kAnswer =
    "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=Asterisk\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n"
    "m=audio 10002 RTP/AVP 8 101\r\na=rtpmap:8 PCMA/8000\r\na=sendrecv\r\n";

TimePoint t0() { return TimePoint{} + 1h; }

TEST(ipv6_sip_uris_via_contact_and_digest_use_bracketed_hosts) {
  auto cfg = config();
  cfg.domain = "2001:db8::1";
  cfg.local_address = "2001:db8::2";
  FakeHost host;
  UserAgent ua(cfg, host);
  ua.start_registration(t0());
  const auto registration = host.last();
  CHECK_EQ(registration.uri, std::string("sip:[2001:db8::1]"));
  CHECK(registration.header("via")->starts_with("SIP/2.0/UDP [2001:db8::2]:50000;"));
  CHECK_EQ(std::string(*registration.header("contact")), std::string("<sip:1001@[2001:db8::2]:50000;transport=udp>"));
  CHECK(registration.header("from")->find("sip:1001@[2001:db8::1]") != std::string_view::npos);
  ua.on_message(respond(registration, 401, kChallenge), t0());
  CHECK(host.last().header("authorization")->find("uri=\"sip:[2001:db8::1]\"") != std::string_view::npos);
  CHECK(ua.call(1, "1002", t0()) == CommandResult::Ok);
  const auto invite = host.last();
  CHECK_EQ(invite.uri, std::string("sip:1002@[2001:db8::1]"));
  CHECK(invite.body.find("c=IN IP6 2001:db8::2\r\n") != std::string::npos);
}

// Checks the digest in an Authorization header the way Asterisk does.
bool digest_valid(const std::string& header_value, const std::string& method) {
  // The challenge parser reads key="value" pairs, which gives realm and nonce back.
  const auto parsed = sip::parse_challenge(header_value);
  if (!parsed) return false;
  const std::string_view rest = header_value;
  const auto grab = [rest](const std::string& key) {
    const size_t at = rest.find(" " + key + "=");
    if (at == std::string_view::npos) return std::string{};
    std::string_view value = rest.substr(at + key.size() + 2);
    if (value.front() == '"') return std::string(value.substr(1, value.find('"', 1) - 1));
    return std::string(value.substr(0, value.find_first_of(", ")));
  };
  const std::string uri = grab("uri");
  const std::string response = grab("response");
  const std::string cnonce = grab("cnonce");
  const std::string nc = grab("nc");
  sip::Challenge challenge = *parsed;
  challenge.qop_auth = !cnonce.empty();
  return sip::digest_response({"1001", "secret"}, challenge, method, uri, nc, cnonce) == response;
}

std::vector<Event> events_of(UserAgent& ua, EventKind kind) {
  std::vector<Event> out;
  for (auto& event : ua.take_events()) {
    if (event.kind == kind) out.push_back(event);
  }
  return out;
}

// Registers the agent and discards the traffic.
void register_ok(UserAgent& ua, FakeHost& host) {
  ua.start_registration(t0());
  ua.on_message(respond(host.last(), 401, kChallenge), t0());
  ua.on_message(respond(host.last(), 200, "Expires: 120\r\n"), t0());
  ua.take_events();
  host.sent.clear();
}

}  // namespace

TEST(registers_with_a_digest_answer_to_the_challenge) {
  FakeHost host;
  UserAgent ua(config(), host);
  ua.start_registration(t0());
  const auto first = host.last();
  CHECK_EQ(first.method, std::string("REGISTER"));
  CHECK_EQ(first.uri, std::string("sip:127.0.0.1"));
  CHECK_EQ(std::string(*first.header("expires")), std::string("120"));
  CHECK(std::string(*first.header("contact")).find("sip:1001@192.168.1.20:50000") != std::string::npos);

  ua.on_message(respond(first, 401, kChallenge), t0());
  const auto second = host.last();
  CHECK_EQ(host.sent.size(), size_t{2});
  CHECK(second.header("authorization").has_value());
  CHECK(digest_valid(std::string(*second.header("authorization")), "REGISTER"));
  CHECK_EQ(std::string(*second.header("call-id")), std::string(*first.header("call-id")));
  CHECK(sip::parse_cseq(*second.header("cseq"))->number > sip::parse_cseq(*first.header("cseq"))->number);

  ua.on_message(respond(second, 200, "Expires: 90\r\n"), t0());
  const auto events = events_of(ua, EventKind::Registration);
  CHECK_EQ(events.size(), size_t{1});
  CHECK_EQ(events[0].status, 200);
  CHECK(ua.registered());
  // Refreshes at half the granted time.
  CHECK(ua.next_deadline().has_value());
  CHECK(*ua.next_deadline() == t0() + 45s);
  ua.on_timer(t0() + 45s);
  CHECK_EQ(host.last().method, std::string("REGISTER"));
  CHECK(!host.last().header("authorization").has_value());
}

TEST(wrong_password_reports_the_second_401_and_does_not_loop) {
  FakeHost host;
  UserAgent ua(config(), host);
  ua.start_registration(t0());
  ua.on_message(respond(host.last(), 401, kChallenge), t0());
  ua.on_message(respond(host.last(), 401, kChallenge), t0());
  const auto events = events_of(ua, EventKind::Registration);
  CHECK_EQ(events.size(), size_t{1});
  CHECK_EQ(events[0].status, 401);
  CHECK_EQ(host.sent.size(), size_t{2});
  CHECK(!ua.next_deadline().has_value());
}

TEST(register_retransmits_then_times_out_and_retries_later) {
  FakeHost host;
  UserAgent ua(config(), host);
  ua.start_registration(t0());
  ua.on_timer(t0() + 500ms);
  ua.on_timer(t0() + 1500ms);
  CHECK_EQ(host.sent.size(), size_t{3});
  CHECK_EQ(host.at(1).header("via").value(), host.at(0).header("via").value());
  ua.on_timer(t0() + 32s);
  const auto events = events_of(ua, EventKind::Registration);
  CHECK_EQ(events.size(), size_t{1});
  CHECK_EQ(events[0].status, 408);
  CHECK(*ua.next_deadline() == t0() + 62s);
}

TEST(outgoing_call_authenticates_rings_answers_and_hangs_up) {
  FakeHost host;
  UserAgent ua(config(), host);
  register_ok(ua, host);

  CHECK(ua.call(7, "*43", t0()) == CommandResult::Ok);
  const auto invite = host.last();
  CHECK_EQ(invite.method, std::string("INVITE"));
  CHECK_EQ(invite.uri, std::string("sip:*43@127.0.0.1"));
  CHECK(invite.body.find("m=audio 40000 RTP/AVP 8 101") != std::string::npos);
  CHECK(invite.body.find("c=IN IP4 192.168.1.20") != std::string::npos);

  ua.on_message(respond(invite, 407, kProxyChallenge), t0());
  // The 407 is acknowledged on the INVITE's branch, then the INVITE is resent with credentials.
  const auto ack = host.at(host.sent.size() - 2);
  CHECK_EQ(ack.method, std::string("ACK"));
  CHECK_EQ(ack.header("via").value(), invite.header("via").value());
  const auto authed = host.last();
  CHECK_EQ(authed.method, std::string("INVITE"));
  CHECK(authed.header("proxy-authorization").has_value());
  CHECK(digest_valid(std::string(*authed.header("proxy-authorization")), "INVITE"));

  ua.on_message(respond(authed, 100, {}, ""), t0());
  ua.on_message(respond(authed, 180), t0());
  auto progress = events_of(ua, EventKind::CallProgress);
  CHECK_EQ(progress.size(), size_t{1});
  CHECK_EQ(progress[0].call_id, 7);
  CHECK_EQ(progress[0].status, 180);
  // Ringing stops INVITE retransmission.
  const size_t before = host.sent.size();
  ua.on_timer(t0() + 10s);
  CHECK_EQ(host.sent.size(), before);

  ua.on_message(respond(authed, 200, "Contact: <sip:asterisk@127.0.0.1:5060>\r\n", "srv", kAnswer), t0());
  const auto ack2xx = host.last();
  CHECK_EQ(ack2xx.method, std::string("ACK"));
  CHECK_EQ(ack2xx.uri, std::string("sip:asterisk@127.0.0.1:5060"));
  CHECK(ack2xx.header("via").value() != authed.header("via").value());
  CHECK(std::string(*ack2xx.header("to")).find("tag=srv") != std::string::npos);
  CHECK_EQ(host.media.size(), size_t{1});
  CHECK_EQ(host.media[0].port, uint16_t{10002});
  CHECK_EQ(events_of(ua, EventKind::CallAnswered).size(), size_t{1});

  // A retransmitted 200 gets the same ACK again.
  ua.on_message(respond(authed, 200, "Contact: <sip:asterisk@127.0.0.1:5060>\r\n", "srv", kAnswer), t0());
  CHECK_EQ(host.last().header("via").value(), ack2xx.header("via").value());

  CHECK(ua.hangup(7, t0()) == CommandResult::Ok);
  const auto bye = host.last();
  CHECK_EQ(bye.method, std::string("BYE"));
  CHECK_EQ(bye.uri, std::string("sip:asterisk@127.0.0.1:5060"));
  const auto ended = events_of(ua, EventKind::CallEnded);
  CHECK_EQ(ended.size(), size_t{1});
  CHECK(ended[0].end_reason == EndReason::Local);
  CHECK_EQ(host.media_closed, 1);
  ua.on_message(respond(bye, 200), t0());
  CHECK(ua.idle());
}

TEST(busy_callee_ends_the_call_as_rejected_with_the_status) {
  FakeHost host;
  UserAgent ua(config(), host);
  register_ok(ua, host);
  ua.call(8, "1002", t0());
  const auto invite = host.last();
  ua.on_message(respond(invite, 486), t0());
  CHECK_EQ(host.last().method, std::string("ACK"));
  const auto ended = events_of(ua, EventKind::CallEnded);
  CHECK_EQ(ended.size(), size_t{1});
  CHECK(ended[0].end_reason == EndReason::Rejected);
  CHECK_EQ(ended[0].status, 486);
  CHECK(!ua.has_call());
  CHECK(ua.call(9, "1002", t0()) == CommandResult::Ok);
}

TEST(hangup_before_any_response_waits_for_a_provisional_to_cancel) {
  FakeHost host;
  UserAgent ua(config(), host);
  register_ok(ua, host);
  ua.call(5, "1002", t0());
  const auto invite = host.last();
  CHECK(ua.hangup(5, t0()) == CommandResult::Ok);
  CHECK_EQ(host.last().method, std::string("INVITE"));  // no CANCEL yet
  ua.on_message(respond(invite, 100, {}, ""), t0());
  const auto cancel = host.last();
  CHECK_EQ(cancel.method, std::string("CANCEL"));
  CHECK_EQ(cancel.header("via").value(), invite.header("via").value());
  CHECK_EQ(sip::parse_cseq(*cancel.header("cseq"))->number, sip::parse_cseq(*invite.header("cseq"))->number);
  ua.on_message(respond(cancel, 200), t0());
  ua.on_message(respond(invite, 487), t0());
  const auto ended = events_of(ua, EventKind::CallEnded);
  CHECK_EQ(ended.size(), size_t{1});
  CHECK(ended[0].end_reason == EndReason::Local);
  CHECK_EQ(ended[0].status, 487);
}

TEST(answer_racing_a_cancel_is_acknowledged_and_hung_up) {
  FakeHost host;
  UserAgent ua(config(), host);
  register_ok(ua, host);
  ua.call(6, "1002", t0());
  const auto invite = host.last();
  ua.on_message(respond(invite, 180), t0());
  ua.hangup(6, t0());
  ua.on_message(respond(invite, 200, "Contact: <sip:a@127.0.0.1>\r\n", "srv", kAnswer), t0());
  CHECK_EQ(host.at(host.sent.size() - 2).method, std::string("ACK"));
  CHECK_EQ(host.last().method, std::string("BYE"));
  CHECK(host.media.empty());
  CHECK_EQ(events_of(ua, EventKind::CallEnded).size(), size_t{1});
}

namespace {
std::string incoming_invite(const std::string& call_id, const std::string& sdp = kAnswer) {
  return "INVITE sip:1001@192.168.1.20:50000 SIP/2.0\r\n"
         "Via: SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bKin1;rport\r\n"
         "From: \"Lan\" <sip:1002@ketviet>;tag=caller\r\n"
         "To: <sip:1001@192.168.1.20:50000>\r\n"
         "Call-ID: " + call_id + "\r\n"
         "CSeq: 102 INVITE\r\n"
         "Contact: <sip:asterisk@127.0.0.1:5060>\r\n"
         "X-KV-Call-Id: 1727000000.42\r\n"
         "Content-Type: application/sdp\r\n"
         "Content-Length: " + std::to_string(sdp.size()) + "\r\n\r\n" + sdp;
}

std::string in_dialog(const std::string& method, const std::string& call_id, int cseq, const std::string& to_tag) {
  return method + " sip:1001@192.168.1.20:50000 SIP/2.0\r\n"
         "Via: SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bK" + method + std::to_string(cseq) + "\r\n"
         "From: \"Lan\" <sip:1002@ketviet>;tag=caller\r\n"
         "To: <sip:1001@192.168.1.20:50000>;tag=" + to_tag + "\r\n"
         "Call-ID: " + call_id + "\r\n"
         "CSeq: " + std::to_string(cseq) + " " + method + "\r\n"
         "Content-Length: 0\r\n\r\n";
}
}  // namespace

TEST(incoming_call_rings_answers_on_command_and_confirms_on_ack) {
  FakeHost host;
  UserAgent ua(config(), host);
  register_ok(ua, host);
  ua.on_message(incoming_invite("in-1"), t0());
  const auto ringing = host.last();
  CHECK_EQ(ringing.status, 180);
  const std::string tag = *sip::param_of(*ringing.header("to"), "tag");
  auto incoming = events_of(ua, EventKind::CallIncoming);
  CHECK_EQ(incoming.size(), size_t{1});
  CHECK_EQ(incoming[0].remote, std::string("sip:1002@ketviet"));
  CHECK_EQ(incoming[0].remote_display_name, std::string("Lan"));
  CHECK_EQ(incoming[0].correlation_id, std::string("1727000000.42"));
  const int32_t id = incoming[0].call_id;

  // A retransmitted INVITE gets the same 180 again, not a second call.
  const size_t sent_before_retransmission = host.sent.size();
  ua.on_message(incoming_invite("in-1"), t0());
  CHECK_EQ(host.sent.size(), sent_before_retransmission + 1);
  CHECK_EQ(host.last().status, 180);
  CHECK(events_of(ua, EventKind::CallIncoming).empty());

  CHECK(ua.answer(id, t0()) == CommandResult::Ok);
  const auto ok = host.last();
  CHECK_EQ(ok.status, 200);
  CHECK(ok.body.find("m=audio 40000") != std::string::npos);
  CHECK_EQ(*sip::param_of(*ok.header("to"), "tag"), tag);
  CHECK_EQ(host.media.size(), size_t{1});
  // Until the ACK arrives the 200 is retransmitted.
  ua.on_timer(t0() + 500ms);
  CHECK_EQ(host.last().status, 200);

  ua.on_message(in_dialog("ACK", "in-1", 102, tag), t0() + 600ms);
  CHECK_EQ(events_of(ua, EventKind::CallAnswered).size(), size_t{1});
  const size_t before = host.sent.size();
  ua.on_timer(t0() + 5s);
  CHECK_EQ(host.sent.size(), before);

  ua.on_message(in_dialog("BYE", "in-1", 103, tag), t0() + 6s);
  CHECK_EQ(host.last().status, 200);
  const auto ended = events_of(ua, EventKind::CallEnded);
  CHECK_EQ(ended.size(), size_t{1});
  CHECK(ended[0].end_reason == EndReason::RemoteHangup);
}

TEST(incoming_call_cancelled_by_the_caller) {
  FakeHost host;
  UserAgent ua(config(), host);
  ua.on_message(incoming_invite("in-2"), t0());
  ua.take_events();
  ua.on_message(in_dialog("CANCEL", "in-2", 102, ""), t0());
  CHECK_EQ(host.at(host.sent.size() - 2).status, 200);
  const auto terminated = host.last();
  CHECK_EQ(terminated.status, 487);
  CHECK_EQ(sip::parse_cseq(*terminated.header("cseq"))->method, std::string("INVITE"));
  const auto ended = events_of(ua, EventKind::CallEnded);
  CHECK_EQ(ended.size(), size_t{1});
  CHECK(ended[0].end_reason == EndReason::RemoteCancelled);
  CHECK_EQ(host.media_opened, 0);
}

TEST(second_incoming_call_is_busy_and_bad_offers_are_refused) {
  FakeHost host;
  UserAgent ua(config(), host);
  ua.on_message(incoming_invite("in-3"), t0());
  ua.on_message(incoming_invite("in-4"), t0());
  CHECK_EQ(host.last().status, 486);
  CHECK_EQ(events_of(ua, EventKind::CallIncoming).size(), size_t{1});

  FakeHost other;
  UserAgent ua2(config(), other);
  const std::string ulaw = "v=0\r\nc=IN IP4 127.0.0.1\r\nm=audio 10002 RTP/AVP 0\r\n";
  ua2.on_message(incoming_invite("in-5", ulaw), t0());
  CHECK_EQ(other.last().status, 488);
  CHECK(!ua2.has_call());
}

TEST(answers_options_and_refuses_unknown_requests) {
  FakeHost host;
  UserAgent ua(config(), host);
  ua.on_message(in_dialog("OPTIONS", "q-1", 1, ""), t0());
  CHECK_EQ(host.last().status, 200);
  CHECK(host.last().header("allow").has_value());
  ua.on_message(in_dialog("BYE", "unknown", 2, "x"), t0());
  CHECK_EQ(host.last().status, 481);
  ua.on_message(in_dialog("MESSAGE", "q-2", 3, ""), t0());
  CHECK_EQ(host.last().status, 501);
  ua.on_message("\r\n\r\n", t0());  // keep-alive
  CHECK_EQ(host.sent.size(), size_t{3});
}

TEST(shutdown_ends_the_call_and_unregisters) {
  FakeHost host;
  UserAgent ua(config(), host);
  register_ok(ua, host);
  ua.call(3, "1002", t0());
  const auto invite = host.last();
  ua.on_message(respond(invite, 180), t0());
  ua.take_events();
  ua.shutdown(t0());
  const auto ended = events_of(ua, EventKind::CallEnded);
  CHECK_EQ(ended.size(), size_t{1});
  CHECK(ended[0].end_reason == EndReason::Shutdown);
  bool cancelled = false;
  bool unregistered = false;
  for (size_t i = 0; i < host.sent.size(); ++i) {
    const auto message = host.at(i);
    cancelled = cancelled || message.method == "CANCEL";
    unregistered = unregistered || (message.method == "REGISTER" && message.header("expires").value_or("") == "0");
  }
  CHECK(cancelled);
  CHECK(unregistered);
  CHECK(!ua.idle());
  CHECK(ua.call(4, "1002", t0()) == CommandResult::State);
}

// Over TLS, with SRTP -----------------------------------------------------------------------------

namespace {

UserAgentConfig secure_config() {
  auto out = config();
  out.transport = "TLS";
  out.local_port = 0;
  out.srtp = true;
  return out;
}

std::vector<uint8_t> test_key(uint8_t seed) {
  std::vector<uint8_t> key(sip::kSdesKeyLength);
  for (size_t n = 0; n < key.size(); ++n) key[n] = static_cast<uint8_t>(seed + n);
  return key;
}

// What Asterisk answers or offers with media_encryption=sdes: keys under RTP/AVP unless the other
// side asked for RTP/SAVP.
std::string secure_sdp(uint32_t tag, const std::vector<uint8_t>& key, bool savp = false, uint16_t port = 10002) {
  return sip::build_audio_sdp("127.0.0.1", port, 1, 1, sip::LocalCrypto{savp, tag, key});
}

std::vector<uint8_t> offered_key(const sip::Message& message) {
  const auto audio = sip::parse_audio(message.body);
  CHECK(audio.has_value());
  CHECK_EQ(audio->crypto.size(), size_t{1});
  return audio->crypto[0].key;
}

}  // namespace

TEST(tls_transport_names_tls_without_a_port_and_never_retransmits) {
  FakeHost host;
  UserAgent ua(secure_config(), host);
  ua.start_registration(t0());
  const auto registration = host.last();
  CHECK(registration.header("via")->starts_with("SIP/2.0/TLS 192.168.1.20;branch=z9hG4bK"));
  CHECK_EQ(std::string(*registration.header("contact")), std::string("<sip:1001@192.168.1.20;transport=tls>"));
  ua.on_timer(t0() + 4s);
  ua.on_timer(t0() + 20s);
  CHECK_EQ(host.sent.size(), size_t{1});
  // The transaction still times out: a connection can die without either side noticing.
  ua.on_timer(t0() + 33s);
  const auto registrations = events_of(ua, EventKind::Registration);
  CHECK_EQ(registrations.size(), size_t{1});
  CHECK_EQ(registrations[0].status, 408);
}

TEST(secure_outgoing_call_offers_its_key_and_uses_the_one_answered) {
  FakeHost host;
  UserAgent ua(secure_config(), host);
  register_ok(ua, host);
  CHECK(ua.call(7, "1002", t0()) == CommandResult::Ok);
  const auto invite = host.last();
  CHECK(invite.body.find("m=audio 40000 RTP/SAVP 8 101\r\n") != std::string::npos);
  CHECK(invite.body.find("a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:") != std::string::npos);
  const auto mine = offered_key(invite);
  CHECK(mine != std::vector<uint8_t>(sip::kSdesKeyLength, 0));
  // Every call gets a fresh key.
  FakeHost other_host;
  UserAgent other(secure_config(), other_host);
  CHECK(other.call(8, "1002", t0()) == CommandResult::Ok);
  CHECK(offered_key(other_host.last()) != mine);

  const auto theirs = test_key(9);
  ua.on_message(respond(invite, 200, "Contact: <sip:asterisk@127.0.0.1:5061;transport=tls>\r\n", "srv",
                        secure_sdp(1, theirs, true)),
                t0());
  CHECK_EQ(host.last().method, std::string("ACK"));
  CHECK_EQ(host.media.size(), size_t{1});
  CHECK(host.media[0].srtp.has_value());
  CHECK(host.media[0].srtp->local == mine);
  CHECK(host.media[0].srtp->remote == theirs);
  CHECK_EQ(events_of(ua, EventKind::CallAnswered).size(), size_t{1});
}

TEST(secure_call_answered_without_its_key_is_hung_up) {
  const std::vector<std::string> answers = {
      kAnswer,                         // plain RTP
      secure_sdp(2, test_key(9), true),  // a key, but not for the line this side offered
  };
  for (const auto& body : answers) {
    FakeHost host;
    UserAgent ua(secure_config(), host);
    CHECK(ua.call(7, "1002", t0()) == CommandResult::Ok);
    const auto invite = host.last();
    ua.on_message(respond(invite, 200, "Contact: <sip:asterisk@127.0.0.1:5061>\r\n", "srv", body), t0());
    CHECK_EQ(host.at(host.sent.size() - 2).method, std::string("ACK"));
    CHECK_EQ(host.last().method, std::string("BYE"));
    CHECK(host.media.empty());
    const auto ended = events_of(ua, EventKind::CallEnded);
    CHECK_EQ(ended.size(), size_t{1});
    CHECK(ended[0].end_reason == EndReason::MediaFailed);
  }
}

TEST(secure_incoming_call_answers_under_the_offers_tag_and_profile) {
  FakeHost host;
  UserAgent ua(secure_config(), host);
  const auto theirs = test_key(40);
  ua.on_message(incoming_invite("sec-1", secure_sdp(5, theirs)), t0());
  CHECK_EQ(host.last().status, 180);
  const int32_t id = events_of(ua, EventKind::CallIncoming).at(0).call_id;
  CHECK(ua.answer(id, t0()) == CommandResult::Ok);
  const auto ok = host.last();
  CHECK_EQ(ok.status, 200);
  // Asterisk offered keys under RTP/AVP, so the answer stays on RTP/AVP and takes tag 5.
  CHECK(ok.body.find("m=audio 40000 RTP/AVP 8 101\r\n") != std::string::npos);
  CHECK(ok.body.find("a=crypto:5 AES_CM_128_HMAC_SHA1_80 inline:") != std::string::npos);
  const auto mine = offered_key(ok);
  CHECK_EQ(host.media.size(), size_t{1});
  CHECK(host.media[0].srtp->remote == theirs);
  CHECK(host.media[0].srtp->local == mine);
  CHECK(mine != theirs);
}

TEST(secure_agent_refuses_plain_offers_and_plain_agent_refuses_savp) {
  FakeHost secure_host;
  UserAgent secure(secure_config(), secure_host);
  secure.on_message(incoming_invite("sec-2"), t0());
  CHECK_EQ(secure_host.last().status, 488);
  CHECK(!secure.has_call());

  FakeHost plain_host;
  UserAgent plain(config(), plain_host);
  plain.on_message(incoming_invite("sec-3", secure_sdp(1, test_key(1), true)), t0());
  CHECK_EQ(plain_host.last().status, 488);
  CHECK(!plain.has_call());
  // Optimistic keys under RTP/AVP are fine for a plain agent: it answers without them.
  plain.on_message(incoming_invite("sec-4", secure_sdp(1, test_key(1))), t0());
  CHECK_EQ(plain_host.last().status, 180);
  CHECK(plain.answer(events_of(plain, EventKind::CallIncoming).at(0).call_id, t0()) == CommandResult::Ok);
  CHECK_EQ(plain_host.last().status, 200);
  CHECK(plain_host.last().body.find("a=crypto") == std::string::npos);
  CHECK(!plain_host.media.at(0).srtp.has_value());
}

TEST(media_refusing_the_keys_ends_the_call_before_any_answer) {
  FakeHost host;
  host.accept_media = false;
  UserAgent ua(secure_config(), host);
  ua.on_message(incoming_invite("sec-5", secure_sdp(1, test_key(3))), t0());
  CHECK(ua.answer(events_of(ua, EventKind::CallIncoming).at(0).call_id, t0()) == CommandResult::Ok);
  CHECK_EQ(host.last().status, 500);
  CHECK(host.last().body.find("a=crypto") == std::string::npos);
  auto ended = events_of(ua, EventKind::CallEnded);
  CHECK_EQ(ended.size(), size_t{1});
  CHECK(ended[0].end_reason == EndReason::MediaFailed);

  FakeHost outgoing_host;
  outgoing_host.accept_media = false;
  UserAgent outgoing(secure_config(), outgoing_host);
  CHECK(outgoing.call(7, "1002", t0()) == CommandResult::Ok);
  outgoing.on_message(respond(outgoing_host.last(), 200, "Contact: <sip:a@127.0.0.1>\r\n", "srv",
                              secure_sdp(1, test_key(3), true)),
                      t0());
  CHECK_EQ(outgoing_host.last().method, std::string("BYE"));
  ended = events_of(outgoing, EventKind::CallEnded);
  CHECK_EQ(ended.size(), size_t{1});
  CHECK(ended[0].end_reason == EndReason::MediaFailed);
}

TEST(secure_reinvite_follows_new_keys_and_refuses_dropping_them) {
  FakeHost host;
  UserAgent ua(secure_config(), host);
  ua.on_message(incoming_invite("sec-6", secure_sdp(1, test_key(10))), t0());
  CHECK(ua.answer(events_of(ua, EventKind::CallIncoming).at(0).call_id, t0()) == CommandResult::Ok);
  const auto ok = host.last();
  const std::string tag = *sip::param_of(*ok.header("to"), "tag");
  const auto mine = offered_key(ok);
  ua.on_message(in_dialog("ACK", "sec-6", 102, tag), t0());

  const auto reinvite = [&](const std::string& body, int cseq) {
    std::string request = in_dialog("INVITE", "sec-6", cseq, tag);
    request.replace(request.find("Content-Length: 0"), 17,
                    "Content-Type: application/sdp\r\nContent-Length: " + std::to_string(body.size()));
    return request + body;
  };
  ua.on_message(reinvite(secure_sdp(2, test_key(20), false, 10010), 103), t0());
  const auto moved = host.last();
  CHECK_EQ(moved.status, 200);
  CHECK(moved.body.find("a=crypto:2 ") != std::string::npos);
  CHECK(offered_key(moved) == mine);  // this side's key stays for the whole call
  CHECK_EQ(host.media.size(), size_t{2});
  CHECK_EQ(host.media[1].port, uint16_t{10010});
  CHECK(host.media[1].srtp->remote == test_key(20));

  ua.on_message(reinvite(kAnswer, 104), t0());
  CHECK_EQ(host.last().status, 488);
  CHECK_EQ(host.media.size(), size_t{2});
  CHECK(ua.has_call());
}

TEST(lost_connection_fails_requests_and_drops_registration_until_it_is_back) {
  FakeHost host;
  UserAgent ua(secure_config(), host);
  register_ok(ua, host);
  CHECK(ua.call(7, "1002", t0()) == CommandResult::Ok);
  ua.on_transport_down(t0() + 1s);
  auto events = ua.take_events();
  const auto registration = std::find_if(events.begin(), events.end(), [](const Event& e) {
    return e.kind == EventKind::Registration;
  });
  CHECK(registration != events.end());
  CHECK_EQ(registration->status, 503);
  const auto ended = std::find_if(events.begin(), events.end(), [](const Event& e) {
    return e.kind == EventKind::CallEnded;
  });
  CHECK(ended != events.end());
  CHECK(!ua.has_call());

  host.sent.clear();
  ua.on_transport_up(t0() + 2s);
  CHECK_EQ(host.sent.size(), size_t{1});
  CHECK_EQ(host.last().method, std::string("REGISTER"));
  CHECK_EQ(std::string(*host.last().header("expires")), std::string("120"));
  // A second notice while that REGISTER is out sends nothing more.
  ua.on_transport_up(t0() + 2s);
  CHECK_EQ(host.sent.size(), size_t{1});

  FakeHost idle_host;
  UserAgent idle(secure_config(), idle_host);
  idle.on_transport_up(t0());
  CHECK(idle_host.sent.empty());  // nobody asked to register
  idle.on_transport_down(t0());
  CHECK(idle.take_events().empty());
}

// Ringing tone and early media -------------------------------------------------------------------

namespace {

// An outgoing call whose INVITE is on the wire, the way the tests below start.
struct Dialling {
  FakeHost host;
  UserAgent ua;
  sip::Message invite;
  Dialling(UserAgentConfig cfg = config()) : ua(std::move(cfg), host) {
    register_ok(ua, host);
    ua.call(7, "1002", t0());
    invite = host.last();
  }
  void reply(int status, const std::string& body = {}, const std::string& extra = {}) {
    ua.on_message(respond(invite, status, extra, "srv", body), t0());
  }
};

const std::string kAnswerContact = "Contact: <sip:asterisk@127.0.0.1:5060>\r\n";

}  // namespace

TEST(a_180_without_sdp_starts_the_ringing_tone_and_opens_no_media) {
  Dialling call;
  call.reply(100);
  CHECK(!call.host.ringing());
  call.reply(180);
  CHECK(call.host.ringing());
  CHECK_EQ(call.host.ringback_started, 1);
  CHECK(call.host.media.empty());
  CHECK_EQ(events_of(call.ua, EventKind::CallProgress).size(), size_t{1});
  // Asterisk repeats the 180 on a retransmission; the tone is not restarted.
  call.reply(180);
  CHECK_EQ(call.host.ringback_started, 1);
}

TEST(a_183_with_sdp_opens_the_far_ends_media_and_plays_no_tone_over_it) {
  Dialling call;
  call.reply(183, kAnswer);
  CHECK_EQ(call.host.media.size(), size_t{1});
  CHECK_EQ(call.host.media[0].port, uint16_t{10002});
  CHECK_EQ(call.host.media[0].address, std::string("127.0.0.1"));
  CHECK_EQ(call.host.ringback_started, 0);
  const auto progress = events_of(call.ua, EventKind::CallProgress);
  CHECK_EQ(progress.size(), size_t{1});
  CHECK_EQ(progress[0].status, 183);
  // A 180 after the early media does not bring the tone on top of the carrier's own sound.
  call.reply(180);
  CHECK_EQ(call.host.ringback_started, 0);
}

TEST(early_media_after_a_180_takes_over_from_the_ringing_tone) {
  Dialling call;
  call.reply(180);
  CHECK(call.host.ringing());
  call.reply(183, kAnswer);
  CHECK(!call.host.ringing());
  CHECK_EQ(call.host.ringback_stopped, 1);
  CHECK_EQ(call.host.media.size(), size_t{1});
  const auto progress = events_of(call.ua, EventKind::CallProgress);
  CHECK_EQ(progress.size(), size_t{2});  // ringing, then early media
}

TEST(a_180_after_the_cancel_does_not_bring_the_ringing_tone_back) {
  Dialling call;
  call.reply(180);
  CHECK(call.host.ringing());
  CHECK(call.ua.hangup(7, t0()) == CommandResult::Ok);
  CHECK(!call.host.ringing());
  CHECK_EQ(call.host.last().method, std::string("CANCEL"));
  // A late or repeated 180 from the server, and a 183 with the carrier's sound, before the 487.
  call.reply(180);
  call.reply(183, kAnswer);
  CHECK(!call.host.ringing());
  CHECK_EQ(call.host.ringback_started, 1);
  CHECK(call.host.media.empty());
}

TEST(a_180_after_a_cancel_that_waited_for_a_provisional_does_not_start_the_tone) {
  Dialling call;
  CHECK(call.ua.hangup(7, t0()) == CommandResult::Ok);  // nothing has answered yet: the CANCEL waits
  call.reply(180);
  CHECK_EQ(call.host.last().method, std::string("CANCEL"));
  call.reply(180);
  CHECK_EQ(call.host.ringback_started, 0);
  CHECK(call.host.media.empty());
}

TEST(a_183_the_agent_cannot_use_leaves_the_ringing_tone_to_the_180) {
  Dialling call;
  // No SDP, only another codec, and a stream the far end will not send on: none is early media.
  call.reply(183);
  CHECK(call.host.media.empty());
  CHECK_EQ(call.host.ringback_started, 0);
  call.reply(183,
             "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=x\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n"
             "m=audio 10002 RTP/AVP 18\r\na=rtpmap:18 G729/8000\r\n");
  CHECK(call.host.media.empty());
  call.reply(180);
  CHECK(call.host.ringing());
  CHECK(call.host.media.empty());
}

TEST(the_ringing_tone_stops_when_the_call_is_answered) {
  Dialling call;
  call.reply(180);
  CHECK(call.host.ringing());
  call.reply(200, kAnswer, kAnswerContact);
  CHECK(!call.host.ringing());
  CHECK_EQ(call.host.media.size(), size_t{1});
  CHECK_EQ(events_of(call.ua, EventKind::CallAnswered).size(), size_t{1});
}

TEST(early_media_is_followed_into_the_answer) {
  Dialling call;
  call.reply(183, kAnswer);
  call.reply(200, kAnswer, kAnswerContact);
  // The 200's description is applied as well, in case it moved the far end.
  CHECK_EQ(call.host.media.size(), size_t{2});
  CHECK_EQ(events_of(call.ua, EventKind::CallAnswered).size(), size_t{1});
  CHECK_EQ(call.host.ringback_started, 0);
}

TEST(the_ringing_tone_stops_at_once_when_the_caller_hangs_up) {
  Dialling call;
  call.reply(180);
  CHECK(call.host.ringing());
  CHECK(call.ua.hangup(7, t0()) == CommandResult::Ok);
  CHECK(!call.host.ringing());  // before the server's 487
  const auto cancel = call.host.last();
  CHECK_EQ(cancel.method, std::string("CANCEL"));
  call.ua.on_message(respond(cancel, 200), t0());
  call.reply(487);
  CHECK(!call.ua.has_call());
  CHECK_EQ(call.host.ringback_stopped, 1);
}

TEST(the_ringing_tone_stops_when_the_call_is_refused_or_times_out) {
  {
    Dialling call;
    call.reply(180);
    call.reply(486);
    CHECK(!call.host.ringing());
    CHECK(!call.ua.has_call());
  }
  {
    Dialling call;
    call.reply(180);
    call.ua.on_timer(t0() + 5min);  // the INVITE's own timer gives up
    CHECK(!call.host.ringing());
  }
  {
    Dialling call;
    call.reply(180);
    call.ua.shutdown(t0());
    CHECK(!call.host.ringing());
  }
}

TEST(a_ringing_incoming_call_never_starts_the_tone) {
  FakeHost host;
  UserAgent ua(config(), host);
  register_ok(ua, host);
  const std::string invite =
      "INVITE sip:1001@192.168.1.20:50000 SIP/2.0\r\nVia: SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bKx\r\n"
      "From: <sip:1002@ketviet>;tag=f\r\nTo: <sip:1001@ketviet>\r\nCall-ID: in1\r\nCSeq: 1 INVITE\r\n"
      "Contact: <sip:asterisk@127.0.0.1:5060>\r\nContent-Type: application/sdp\r\nContent-Length: " +
      std::to_string(kAnswer.size()) + "\r\n\r\n" + kAnswer;
  ua.on_message(invite, t0());
  CHECK(ua.has_call());
  CHECK(ua.answer(events_of(ua, EventKind::CallIncoming).at(0).call_id, t0()) == CommandResult::Ok);
  CHECK_EQ(host.ringback_started, 0);
  CHECK_EQ(host.ringback_stopped, 0);
  CHECK_EQ(host.media.size(), size_t{1});
}

TEST(secure_early_media_must_take_up_the_offered_key) {
  const auto theirs = test_key(9);
  {
    Dialling call(secure_config());
    call.reply(183, secure_sdp(1, theirs, true));
    CHECK_EQ(call.host.media.size(), size_t{1});
    CHECK(call.host.media[0].srtp.has_value());
    CHECK(call.host.media[0].srtp->remote == theirs);
    CHECK_EQ(call.host.ringback_started, 0);
  }
  {
    // Another tag is not the key this side offered; the sound is not played and the call goes on.
    Dialling call(secure_config());
    call.reply(183, secure_sdp(9, theirs, true));
    CHECK(call.host.media.empty());
    CHECK(call.ua.has_call());
    call.reply(180);
    CHECK(call.host.ringing());
  }
  {
    // Keys the media layer refuses do not end the call; the 200 decides.
    Dialling call(secure_config());
    call.host.accept_media = false;
    call.reply(183, secure_sdp(1, theirs, true));
    CHECK(call.ua.has_call());
    CHECK(!call.host.ringing());
  }
}

// Hold and resume -------------------------------------------------------------------------------

namespace {

// Asterisk's answer, with the telephone-event mapping it sends and the given direction.
std::string answer_sdp(const std::string& direction, uint16_t port = 10002, int event = 101) {
  return "v=0\r\no=- 1 2 IN IP4 127.0.0.1\r\ns=Asterisk\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n"
         "m=audio " + std::to_string(port) + " RTP/AVP 8 " + std::to_string(event) + "\r\na=rtpmap:8 PCMA/8000\r\n"
         "a=rtpmap:" + std::to_string(event) + " telephone-event/8000\r\na=fmtp:" + std::to_string(event) +
         " 0-16\r\na=" + direction + "\r\n";
}

std::string with_body(std::string request, const std::string& body) {
  request.replace(request.find("Content-Length: 0"), 17,
                  "Content-Type: application/sdp\r\nContent-Length: " + std::to_string(body.size()));
  return request + body;
}

const std::string kContact = "Contact: <sip:asterisk@127.0.0.1:5060>\r\n";

// An outgoing call to 1002, answered with `answer` and acknowledged.
void connect_outgoing(UserAgent& ua, FakeHost& host, const std::string& answer = answer_sdp("sendrecv")) {
  register_ok(ua, host);
  CHECK(ua.call(7, "1002", t0()) == CommandResult::Ok);
  ua.on_message(respond(host.last(), 200, kContact, "srv", answer), t0());
  CHECK_EQ(host.last().method, std::string("ACK"));
  CHECK_EQ(events_of(ua, EventKind::CallAnswered).size(), size_t{1});
}

// An incoming call from 1002, answered and acknowledged; returns this side's tag.
std::string connect_incoming(UserAgent& ua, FakeHost& host, int32_t& id) {
  register_ok(ua, host);
  ua.on_message(incoming_invite("hold-in", answer_sdp("sendrecv")), t0());
  id = events_of(ua, EventKind::CallIncoming).at(0).call_id;
  CHECK(ua.answer(id, t0()) == CommandResult::Ok);
  const std::string tag = *sip::param_of(*host.last().header("to"), "tag");
  ua.on_message(in_dialog("ACK", "hold-in", 102, tag), t0());
  ua.take_events();
  return tag;
}

bool has_line(const sip::Message& message, const std::string& line) {
  return message.body.find(line + "\r\n") != std::string::npos;
}

uint32_t cseq_of(const sip::Message& message) { return sip::parse_cseq(*message.header("cseq"))->number; }

}  // namespace

TEST(hold_sends_a_sendonly_reinvite_in_the_dialog_and_stops_media_once_accepted) {
  FakeHost host;
  UserAgent ua(config(), host);
  connect_outgoing(ua, host);
  const auto invite = host.at(0);
  CHECK(host.media.back().send && host.media.back().receive);

  CHECK(ua.hold(7, true, t0()) == CommandResult::Ok);
  const auto reinvite = host.last();
  CHECK_EQ(reinvite.method, std::string("INVITE"));
  CHECK_EQ(reinvite.uri, std::string("sip:asterisk@127.0.0.1:5060"));  // the remote target
  CHECK_EQ(std::string(*reinvite.header("call-id")), std::string(*invite.header("call-id")));
  CHECK(std::string(*reinvite.header("to")).find("tag=srv") != std::string::npos);
  CHECK(cseq_of(reinvite) > cseq_of(invite));
  CHECK(has_line(reinvite, "a=sendonly"));
  CHECK(!has_line(reinvite, "a=sendrecv"));
  // The same session, one version on.
  CHECK(reinvite.body.find("o=- ") != std::string::npos);
  CHECK(sip::parse_audio(reinvite.body)->port == uint16_t{40000});
  // Nothing changes before the far end accepts.
  CHECK(!ua.local_hold());
  CHECK(events_of(ua, EventKind::CallHold).empty());

  const size_t media_before = host.media.size();
  ua.on_message(respond(reinvite, 200, kContact, "srv", answer_sdp("recvonly")), t0());
  const auto ack = host.last();
  CHECK_EQ(ack.method, std::string("ACK"));
  CHECK_EQ(cseq_of(ack), cseq_of(reinvite));
  CHECK(ack.header("via").value() != reinvite.header("via").value());
  CHECK(ua.local_hold());
  CHECK_EQ(host.media.size(), media_before + 1);
  CHECK(!host.media.back().send);
  CHECK(!host.media.back().receive);
  const auto held = events_of(ua, EventKind::CallHold);
  CHECK_EQ(held.size(), size_t{1});
  CHECK_EQ(held[0].call_id, 7);
  CHECK_EQ(held[0].status, 200);
  CHECK(held[0].local_hold);
  CHECK(!held[0].remote_hold);

  // A retransmitted 200 to the re-INVITE gets its own ACK again.
  ua.on_message(respond(reinvite, 200, kContact, "srv", answer_sdp("recvonly")), t0());
  CHECK_EQ(host.last().header("via").value(), ack.header("via").value());

  // DTMF is refused while held.
  CHECK(ua.send_dtmf(7, "1", 0, t0()) == CommandResult::State);

  CHECK(ua.hold(7, false, t0()) == CommandResult::Ok);
  const auto resume = host.last();
  CHECK(has_line(resume, "a=sendrecv"));
  CHECK(cseq_of(resume) > cseq_of(reinvite));
  ua.on_message(respond(resume, 200, kContact, "srv", answer_sdp("sendrecv")), t0());
  CHECK(!ua.local_hold());
  CHECK(host.media.back().send && host.media.back().receive);
  const auto resumed = events_of(ua, EventKind::CallHold);
  CHECK_EQ(resumed.size(), size_t{1});
  CHECK(!resumed[0].local_hold);

  // The BYE comes after both re-INVITEs in the CSeq order.
  CHECK(ua.hangup(7, t0()) == CommandResult::Ok);
  CHECK(cseq_of(host.last()) > cseq_of(resume));
}

TEST(hold_is_refused_before_the_call_connects_and_reports_an_unchanged_state) {
  FakeHost host;
  UserAgent ua(config(), host);
  register_ok(ua, host);
  CHECK(ua.hold(7, true, t0()) == CommandResult::NotFound);
  CHECK(ua.call(7, "1002", t0()) == CommandResult::Ok);
  CHECK(ua.hold(7, true, t0()) == CommandResult::State);
  CHECK(ua.send_dtmf(7, "1", 0, t0()) == CommandResult::State);
  ua.on_message(respond(host.last(), 200, kContact, "srv", answer_sdp("sendrecv")), t0());
  ua.take_events();
  // Resuming a call that is not held sends nothing and says how it stands.
  const size_t sent = host.sent.size();
  CHECK(ua.hold(7, false, t0()) == CommandResult::Ok);
  CHECK_EQ(host.sent.size(), sent);
  const auto events = events_of(ua, EventKind::CallHold);
  CHECK_EQ(events.size(), size_t{1});
  CHECK(!events[0].local_hold);
}

TEST(a_refused_hold_leaves_the_call_as_it_was) {
  FakeHost host;
  UserAgent ua(config(), host);
  connect_outgoing(ua, host);
  CHECK(ua.hold(7, true, t0()) == CommandResult::Ok);
  const auto reinvite = host.last();
  const size_t media_before = host.media.size();
  ua.on_message(respond(reinvite, 488, {}, "srv"), t0());
  CHECK_EQ(host.last().method, std::string("ACK"));
  CHECK_EQ(host.last().header("via").value(), reinvite.header("via").value());  // non-2xx ACK: same branch
  CHECK(!ua.local_hold());
  CHECK(ua.has_call());
  CHECK_EQ(host.media.size(), media_before);
  const auto events = events_of(ua, EventKind::CallHold);
  CHECK_EQ(events.size(), size_t{1});
  CHECK_EQ(events[0].status, 488);
  CHECK(!events[0].local_hold);
  // The call still takes keys.
  CHECK(ua.send_dtmf(7, "5", 0, t0()) == CommandResult::Ok);
}

TEST(hold_authenticates_when_challenged) {
  FakeHost host;
  UserAgent ua(config(), host);
  connect_outgoing(ua, host);
  CHECK(ua.hold(7, true, t0()) == CommandResult::Ok);
  const auto reinvite = host.last();
  ua.on_message(respond(reinvite, 407, kProxyChallenge, "srv"), t0());
  const auto authed = host.last();
  CHECK_EQ(authed.method, std::string("INVITE"));
  CHECK(authed.header("proxy-authorization").has_value());
  CHECK(digest_valid(std::string(*authed.header("proxy-authorization")), "INVITE"));
  CHECK(has_line(authed, "a=sendonly"));
  CHECK_EQ(authed.body, reinvite.body);  // the same offer
  ua.on_message(respond(authed, 200, kContact, "srv", answer_sdp("recvonly")), t0());
  CHECK(ua.local_hold());
}

TEST(a_resume_asked_while_the_hold_is_out_follows_it) {
  FakeHost host;
  UserAgent ua(config(), host);
  connect_outgoing(ua, host);
  CHECK(ua.hold(7, true, t0()) == CommandResult::Ok);
  const auto hold = host.last();
  const size_t sent = host.sent.size();
  CHECK(ua.hold(7, false, t0()) == CommandResult::Ok);
  CHECK_EQ(host.sent.size(), sent);  // one re-INVITE at a time
  ua.on_message(respond(hold, 200, kContact, "srv", answer_sdp("recvonly")), t0());
  const auto resume = host.last();
  CHECK_EQ(resume.method, std::string("INVITE"));
  CHECK(has_line(resume, "a=sendrecv"));
  CHECK_EQ(events_of(ua, EventKind::CallHold).size(), size_t{1});
  ua.on_message(respond(resume, 200, kContact, "srv", answer_sdp("sendrecv")), t0());
  CHECK(!ua.local_hold());
}

TEST(reinvites_that_cross_get_a_491_and_this_side_tries_again_later) {
  FakeHost host;
  UserAgent ua(config(), host);
  int32_t id = 0;
  const std::string tag = connect_incoming(ua, host, id);
  CHECK(ua.hold(id, true, t0()) == CommandResult::Ok);
  const auto first = host.last();
  CHECK_EQ(first.uri, std::string("sip:asterisk@127.0.0.1:5060"));
  // Requests this side sends in the dialog carry its tag in From and the caller's in To.
  CHECK(std::string(*first.header("from")).find("tag=" + tag) != std::string::npos);
  CHECK(std::string(*first.header("to")).find("tag=caller") != std::string::npos);

  // The far end's own re-INVITE crosses ours.
  ua.on_message(with_body(in_dialog("INVITE", "hold-in", 103, tag), answer_sdp("sendrecv")), t0());
  CHECK_EQ(host.last().status, 491);

  ua.on_message(respond(first, 491, {}, ""), t0());
  CHECK_EQ(host.last().method, std::string("ACK"));
  CHECK(events_of(ua, EventKind::CallHold).empty());
  // Not the side that made the call: within 2 s.
  CHECK(ua.next_deadline().has_value());
  CHECK(*ua.next_deadline() <= t0() + 2s);
  ua.on_timer(t0() + 2s);
  const auto again = host.last();
  CHECK_EQ(again.method, std::string("INVITE"));
  CHECK(cseq_of(again) > cseq_of(first));
  CHECK(has_line(again, "a=sendonly"));
  ua.on_message(respond(again, 200, kContact, "", answer_sdp("recvonly")), t0() + 2s);
  CHECK(ua.local_hold());
}

TEST(the_caller_waits_longer_after_a_491) {
  FakeHost host;
  UserAgent ua(config(), host);
  connect_outgoing(ua, host);
  CHECK(ua.hold(7, true, t0()) == CommandResult::Ok);
  ua.on_message(respond(host.last(), 491, {}, "srv"), t0());
  CHECK(*ua.next_deadline() >= t0() + 2100ms);
  CHECK(*ua.next_deadline() <= t0() + 4s);
}

TEST(a_481_or_no_answer_to_the_hold_ends_the_call) {
  {
    FakeHost host;
    UserAgent ua(config(), host);
    connect_outgoing(ua, host);
    CHECK(ua.hold(7, true, t0()) == CommandResult::Ok);
    ua.on_message(respond(host.last(), 481, {}, "srv"), t0());
    const auto ended = events_of(ua, EventKind::CallEnded);
    CHECK_EQ(ended.size(), size_t{1});
    CHECK(ended[0].end_reason == EndReason::RemoteHangup);
    CHECK(!ua.has_call());
  }
  {
    FakeHost host;
    UserAgent ua(config(), host);
    connect_outgoing(ua, host);
    CHECK(ua.hold(7, true, t0()) == CommandResult::Ok);
    ua.on_timer(t0() + 40s);
    CHECK_EQ(host.last().method, std::string("BYE"));
    const auto ended = events_of(ua, EventKind::CallEnded);
    CHECK_EQ(ended.size(), size_t{1});
    CHECK(ended[0].end_reason == EndReason::Timeout);
  }
}

TEST(the_far_ends_hold_is_answered_recvonly_and_reported) {
  FakeHost host;
  UserAgent ua(config(), host);
  int32_t id = 0;
  const std::string tag = connect_incoming(ua, host, id);

  ua.on_message(with_body(in_dialog("INVITE", "hold-in", 103, tag), answer_sdp("sendonly")), t0());
  const auto answer = host.last();
  CHECK_EQ(answer.status, 200);
  CHECK(has_line(answer, "a=recvonly"));
  CHECK(ua.remote_hold());
  // Music on hold plays; nothing is sent to a far end that takes nothing.
  CHECK(!host.media.back().send);
  CHECK(host.media.back().receive);
  auto events = events_of(ua, EventKind::CallHold);
  CHECK_EQ(events.size(), size_t{1});
  CHECK(events[0].remote_hold);
  CHECK(!events[0].local_hold);
  CHECK(ua.send_dtmf(id, "1", 0, t0()) == CommandResult::State);

  // Holding as well: the offer is inactive.
  CHECK(ua.hold(id, true, t0()) == CommandResult::Ok);
  const auto both = host.last();
  CHECK(has_line(both, "a=inactive"));
  ua.on_message(respond(both, 200, kContact, "", answer_sdp("inactive")), t0());
  events = events_of(ua, EventKind::CallHold);
  CHECK_EQ(events.size(), size_t{1});
  CHECK(events[0].local_hold);
  CHECK(events[0].remote_hold);

  // Resuming while the far end still holds asks to receive only.
  CHECK(ua.hold(id, false, t0()) == CommandResult::Ok);
  const auto resume = host.last();
  CHECK(has_line(resume, "a=recvonly"));
  ua.on_message(respond(resume, 200, kContact, "", answer_sdp("sendonly")), t0());
  CHECK(!ua.local_hold());
  events = events_of(ua, EventKind::CallHold);
  CHECK_EQ(events.size(), size_t{1});
  CHECK(!events[0].local_hold);
  CHECK(events[0].remote_hold);
  // Music on hold still plays; nothing is sent yet.
  CHECK(!host.media.back().send);
  CHECK(host.media.back().receive);

  // The far end resumes.
  ua.on_message(with_body(in_dialog("INVITE", "hold-in", 104, tag), answer_sdp("sendrecv")), t0());
  CHECK(has_line(host.last(), "a=sendrecv"));
  CHECK(!ua.remote_hold());
  CHECK(host.media.back().send && host.media.back().receive);
  events = events_of(ua, EventKind::CallHold);
  CHECK_EQ(events.size(), size_t{1});
  CHECK(!events[0].remote_hold);

  // An inactive offer is answered inactive.
  ua.on_message(with_body(in_dialog("INVITE", "hold-in", 105, tag), answer_sdp("inactive")), t0());
  CHECK(has_line(host.last(), "a=inactive"));
  CHECK(ua.remote_hold());
}

TEST(a_reinvite_that_changes_nothing_keeps_the_sdp_version) {
  FakeHost host;
  UserAgent ua(config(), host);
  int32_t id = 0;
  const std::string tag = connect_incoming(ua, host, id);
  const std::string first = host.at(host.sent.size() - 1).body;
  ua.on_message(with_body(in_dialog("INVITE", "hold-in", 103, tag), answer_sdp("sendrecv")), t0());
  const auto same = host.last();
  CHECK_EQ(same.status, 200);
  CHECK_EQ(same.body.substr(0, same.body.find("s=")), first.substr(0, first.find("s=")));
  ua.on_message(with_body(in_dialog("INVITE", "hold-in", 104, tag), answer_sdp("sendonly")), t0());
  const auto changed = host.last();
  CHECK(changed.body.substr(0, changed.body.find("s=")) != first.substr(0, first.find("s=")));
}

// DTMF -------------------------------------------------------------------------------------------

TEST(dtmf_goes_to_the_media_on_the_answered_telephone_event_type) {
  FakeHost host;
  UserAgent ua(config(), host);
  connect_outgoing(ua, host, answer_sdp("sendrecv", 10002, 96));
  CHECK(host.media.back().telephone_event == std::optional<uint8_t>(96));
  CHECK(ua.send_dtmf(7, "12#*", 250, t0()) == CommandResult::Ok);
  CHECK_EQ(host.dtmf.size(), size_t{1});
  CHECK_EQ(host.dtmf[0].first, std::string("12#*"));
  CHECK_EQ(host.dtmf[0].second, uint32_t{250});
  CHECK(ua.send_dtmf(7, "", 0, t0()) == CommandResult::InvalidArgument);
  CHECK(ua.send_dtmf(7, "1x", 0, t0()) == CommandResult::InvalidArgument);
  CHECK(ua.send_dtmf(8, "1", 0, t0()) == CommandResult::NotFound);
  CHECK_EQ(host.dtmf.size(), size_t{1});
}

TEST(dtmf_is_refused_when_the_far_end_named_no_telephone_event_type) {
  FakeHost host;
  UserAgent ua(config(), host);
  connect_outgoing(ua, host, kAnswer);  // lists 101 without an rtpmap for it
  CHECK(!host.media.back().telephone_event.has_value());
  CHECK(ua.send_dtmf(7, "1", 0, t0()) == CommandResult::State);
  CHECK(host.dtmf.empty());
}

TEST(an_answer_uses_the_offers_telephone_event_type_or_leaves_it_out) {
  FakeHost host;
  UserAgent ua(config(), host);
  register_ok(ua, host);
  ua.on_message(incoming_invite("te-1", answer_sdp("sendrecv", 10002, 97)), t0());
  CHECK(ua.answer(events_of(ua, EventKind::CallIncoming).at(0).call_id, t0()) == CommandResult::Ok);
  const auto ok = host.last();
  CHECK(ok.body.find("m=audio 40000 RTP/AVP 8 97\r\n") != std::string::npos);
  CHECK(has_line(ok, "a=rtpmap:97 telephone-event/8000"));
  CHECK(host.media.back().telephone_event == std::optional<uint8_t>(97));

  FakeHost plain_host;
  UserAgent plain(config(), plain_host);
  register_ok(plain, plain_host);
  plain.on_message(incoming_invite("te-2", kAnswer), t0());
  CHECK(plain.answer(events_of(plain, EventKind::CallIncoming).at(0).call_id, t0()) == CommandResult::Ok);
  const auto bare = plain_host.last();
  CHECK(bare.body.find("m=audio 40000 RTP/AVP 8\r\n") != std::string::npos);
  CHECK(bare.body.find("telephone-event") == std::string::npos);
}
