// The user agent against a scripted server: every datagram it sends is parsed and answered the
// way the Asterisk configuration in ketviet's infra/telephony answers it.
#include <chrono>
#include <string>
#include <vector>

#include "check.hpp"
#include "core/user_agent.hpp"
#include "sip/digest.hpp"
#include "sip/message.hpp"

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
  void start_media(const RemoteMedia& remote) override { media.push_back(remote); }
  void close_media() override { ++media_closed; }

  sip::Message last() const { return *sip::parse_message(sent.back()); }
  sip::Message at(size_t index) const { return *sip::parse_message(sent.at(index)); }

  std::vector<std::string> sent;
  std::vector<RemoteMedia> media;
  uint16_t media_port = 40000;
  int media_opened = 0;
  int media_closed = 0;
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

TimePoint t0() { return TimePoint{} + 1h; }

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
