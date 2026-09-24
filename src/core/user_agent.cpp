#include "core/user_agent.hpp"

#include <algorithm>

#include "sip/digest.hpp"
#include "sip/random.hpp"
#include "sip/text.hpp"

namespace ketphone::core {
namespace {

using namespace std::chrono_literals;

// RFC 3261 timers.
constexpr Duration kT1 = 500ms;
constexpr Duration kT2 = 4s;
constexpr Duration kTransactionTimeout = 64 * kT1;
// Once the far end rings, the INVITE waits for a human; the server ends it well before this.
constexpr Duration kInviteAfterProvisional = 3min;
// Retry after a registration timed out or the server failed.
constexpr Duration kRegisterRetry = 30s;
constexpr Duration kMinimumRefresh = 5s;

constexpr const char* kAllow = "INVITE, ACK, CANCEL, BYE, OPTIONS";

std::string tagged(const std::string& header, const std::string& tag) {
  if (sip::param_of(header, "tag")) return header;
  return header + ";tag=" + tag;
}

std::string branch_of(const sip::Message& message) {
  const auto via = message.header("via");
  if (!via) return {};
  // Only the top Via, which may share a header line with others.
  const std::string_view top = via->substr(0, via->find(','));
  return sip::param_of(top, "branch").value_or("");
}

}  // namespace

UserAgent::UserAgent(UserAgentConfig config, UserAgentHost& host) : config_(std::move(config)), host_(host) {
  registration_.call_id = sip::random_hex(12) + "@ketphone";
  registration_.from_tag = sip::random_hex(6);
  registration_.cseq = 1;
  int32_t next = 1000000;
  allocate_call_id = [next]() mutable { return next++; };
}

std::string UserAgent::aor() const { return "sip:" + config_.extension + "@" + config_.domain; }

std::string UserAgent::contact() const {
  return "<sip:" + config_.extension + "@" + config_.local_address + ":" + std::to_string(config_.local_port) +
         ";transport=udp>";
}

std::string UserAgent::via(const std::string& branch) const {
  return "SIP/2.0/UDP " + config_.local_address + ":" + std::to_string(config_.local_port) + ";branch=" + branch +
         ";rport";
}

std::vector<Event> UserAgent::take_events() {
  std::vector<Event> out;
  out.swap(events_);
  return out;
}

void UserAgent::emit(Event event) { events_.push_back(std::move(event)); }

void UserAgent::send_raw(const std::string& message) { host_.send_sip(message); }

std::string UserAgent::build_request(const Request& request, const std::string& branch) const {
  sip::MessageBuilder builder(request.method + " " + request.uri + " SIP/2.0");
  builder.add("Via", via(branch))
      .add("Max-Forwards", "70")
      .add("From", request.from)
      .add("To", request.to)
      .add("Call-ID", request.call_id)
      .add("CSeq", std::to_string(request.cseq) + " " + request.method);
  if (request.method != "ACK" && request.method != "CANCEL") builder.add("Contact", contact());
  for (const auto& [name, value] : request.extra) builder.add(name, value);
  builder.add("User-Agent", config_.user_agent);
  if (!request.body.empty()) builder.body("application/sdp", request.body);
  return builder.build();
}

std::string UserAgent::send_request(const Request& request, TimePoint now, FinalHandler on_final,
                                    ProvisionalHandler on_provisional, std::string branch) {
  if (branch.empty()) branch = "z9hG4bK" + sip::random_hex(10);
  Transaction transaction;
  transaction.method = request.method;
  transaction.bytes = build_request(request, branch);
  transaction.interval = kT1;
  transaction.retransmit_at = now + kT1;
  transaction.deadline = now + kTransactionTimeout;
  transaction.on_final = std::move(on_final);
  transaction.on_provisional = std::move(on_provisional);
  send_raw(transaction.bytes);
  transactions_[branch + " " + request.method] = std::move(transaction);
  return branch;
}

std::string UserAgent::build_response(const sip::Message& request, int32_t status, const std::string& to_tag,
                                      const std::string& body) const {
  sip::MessageBuilder builder("SIP/2.0 " + std::to_string(status) + " " + std::string(sip::reason_phrase(status)));
  for (const auto via_value : request.header_all("via")) builder.add("Via", via_value);
  builder.add("From", request.header("from").value_or(""));
  std::string to(request.header("to").value_or(""));
  if (!to_tag.empty() && status > 100) to = tagged(to, to_tag);
  builder.add("To", to)
      .add("Call-ID", request.header("call-id").value_or(""))
      .add("CSeq", request.header("cseq").value_or(""));
  if (request.method == "INVITE" && status < 300) builder.add("Contact", contact());
  if (request.method == "OPTIONS" || status == 501) builder.add("Allow", kAllow);
  builder.add("User-Agent", config_.user_agent);
  if (!body.empty()) builder.body("application/sdp", body);
  return builder.build();
}

std::optional<std::string> UserAgent::authorization_for(const sip::Message& challenge, const std::string& method,
                                                        const std::string& uri) const {
  const bool proxy = challenge.status == 407;
  const auto value = challenge.header(proxy ? "proxy-authenticate" : "www-authenticate");
  if (!value) return std::nullopt;
  const auto parsed = sip::parse_challenge(*value);
  if (!parsed) return std::nullopt;
  const auto authorization =
      sip::authorization_value({config_.extension, config_.password}, *parsed, method, uri);
  if (!authorization) return std::nullopt;
  return std::string(proxy ? "Proxy-Authorization" : "Authorization") + ": " + *authorization;
}

// Registration --------------------------------------------------------------------------------

void UserAgent::start_registration(TimePoint now) {
  if (shutting_down_) return;
  registration_.wanted = true;
  registration_.next_attempt.reset();
  if (!registration_.in_flight) send_register(config_.register_expires, {}, now);
}

void UserAgent::stop_registration(TimePoint now) {
  registration_.wanted = false;
  registration_.next_attempt.reset();
  if (registration_.registered || registration_.in_flight) {
    registration_.registered = false;
    send_register(0, {}, now);
  }
}

void UserAgent::send_register(uint32_t expires, const std::string& authorization, TimePoint now) {
  Request request;
  request.method = "REGISTER";
  request.uri = "sip:" + config_.domain;
  request.from = "<" + aor() + ">;tag=" + registration_.from_tag;
  request.to = "<" + aor() + ">";
  request.call_id = registration_.call_id;
  request.cseq = registration_.cseq++;
  request.extra.emplace_back("Expires", std::to_string(expires));
  request.extra.emplace_back("Allow", kAllow);
  const bool authenticated = !authorization.empty();
  if (authenticated) {
    const size_t colon = authorization.find(':');
    request.extra.emplace_back(authorization.substr(0, colon), std::string(sip::trim(authorization.substr(colon + 1))));
  }
  registration_.in_flight = true;
  send_request(request, now, [this, expires, authenticated](const sip::Message* response, TimePoint at) {
    on_register_final(response, expires, authenticated, at);
  });
}

void UserAgent::on_register_final(const sip::Message* response, uint32_t expires, bool authenticated, TimePoint now) {
  registration_.in_flight = false;
  const int32_t status = response ? response->status : 408;
  if (response && (status == 401 || status == 407) && !authenticated) {
    if (const auto authorization = authorization_for(*response, "REGISTER", "sip:" + config_.domain)) {
      send_register(expires, *authorization, now);
      return;
    }
  }
  if (expires == 0) return;  // an unregister; nothing to report

  // A registration requested before this one finished (or after a stop) takes precedence.
  if (!registration_.wanted) {
    if (status >= 200 && status < 300) send_register(0, {}, now);
    return;
  }

  if (status >= 200 && status < 300) {
    uint32_t granted = expires;
    if (const auto header = response->header("expires")) {
      granted = sip::parse_integer<uint32_t>(*header).value_or(granted);
    } else {
      for (const auto value : response->header_all("contact")) {
        if (sip::uri_of(value).find(config_.local_address) == std::string::npos) continue;
        if (const auto param = sip::param_of(value, "expires")) {
          granted = sip::parse_integer<uint32_t>(*param).value_or(granted);
        }
      }
    }
    registration_.registered = true;
    const Duration refresh = std::max<Duration>(std::chrono::seconds(granted) / 2, kMinimumRefresh);
    registration_.next_attempt = now + refresh;
  } else {
    registration_.registered = false;
    // Wrong credentials or a forbidden account will not fix themselves; transient failures might.
    if (status == 408 || status >= 500) registration_.next_attempt = now + kRegisterRetry;
  }
  Event event;
  event.kind = EventKind::Registration;
  event.status = status;
  emit(std::move(event));
}

// Outgoing calls --------------------------------------------------------------------------------

CommandResult UserAgent::call(int32_t call_id, const std::string& target, TimePoint now) {
  if (target.empty() || target.find_first_of(" \t\r\n<>\"@;") != std::string::npos) {
    return CommandResult::InvalidArgument;
  }
  if (call_ || shutting_down_) return CommandResult::State;

  const uint16_t port = host_.open_media();
  Call call;
  call.id = call_id;
  call.outgoing = true;
  call.state = CallState::Calling;
  call.sip_call_id = sip::random_hex(12) + "@ketphone";
  call.local_tag = sip::random_hex(6);
  call.invite_uri = "sip:" + target + "@" + config_.domain;
  call.remote_uri = call.invite_uri;
  call.local_header = "<" + aor() + ">;tag=" + call.local_tag;
  call.remote_header = "<" + call.invite_uri + ">";
  call.local_cseq = 1;
  call.media_open = port != 0;
  call_ = std::move(call);
  if (port == 0) {
    end_call(EndReason::MediaFailed, 0);
    return CommandResult::Ok;
  }
  call_->local_sdp = sip::build_audio_sdp(config_.local_address, port, sip::random_u32(), 1);
  send_invite({}, now);
  return CommandResult::Ok;
}

void UserAgent::send_invite(const std::string& authorization, TimePoint now) {
  Call& call = *call_;
  Request request;
  request.method = "INVITE";
  request.uri = call.invite_uri;
  request.from = call.local_header;
  request.to = "<" + call.invite_uri + ">";
  request.call_id = call.sip_call_id;
  request.cseq = call.local_cseq++;
  request.extra.emplace_back("Allow", kAllow);
  if (!authorization.empty()) {
    const size_t colon = authorization.find(':');
    request.extra.emplace_back(authorization.substr(0, colon), std::string(sip::trim(authorization.substr(colon + 1))));
  }
  request.body = call.local_sdp;

  InviteContext context;
  context.call_id = call.id;
  context.uri = request.uri;
  context.from = request.from;
  context.sip_call_id = request.call_id;
  context.cseq = request.cseq;
  context.branch = "z9hG4bK" + sip::random_hex(10);

  call.invite_cseq = request.cseq;
  call.invite_branch = context.branch;
  call.provisional = false;
  const int32_t id = call.id;
  send_request(
      request, now,
      [this, context](const sip::Message* response, TimePoint at) { on_invite_final(context, response, at); },
      [this, id](const sip::Message& response, TimePoint at) { on_invite_provisional(id, response, at); }, context.branch);
}

void UserAgent::on_invite_provisional(int32_t call_id, const sip::Message& response, TimePoint now) {
  if (!call_ || call_->id != call_id || call_->state != CallState::Calling) return;
  call_->provisional = true;
  if (call_->cancel_requested && !call_->cancel_sent) {
    send_cancel(now);
    return;
  }
  if ((response.status == 180 || response.status == 183) && call_->last_progress != response.status) {
    call_->last_progress = response.status;
    Event event;
    event.kind = EventKind::CallProgress;
    event.call_id = call_id;
    event.status = response.status;
    event.remote = call_->remote_uri;
    emit(std::move(event));
  }
}

void UserAgent::send_ack_for_failure(const InviteContext& context, const sip::Message& response) {
  sip::MessageBuilder builder("ACK " + context.uri + " SIP/2.0");
  builder.add("Via", via(context.branch))
      .add("Max-Forwards", "70")
      .add("From", context.from)
      .add("To", response.header("to").value_or(""))
      .add("Call-ID", context.sip_call_id)
      .add("CSeq", std::to_string(context.cseq) + " ACK")
      .add("User-Agent", config_.user_agent);
  send_raw(builder.build());
}

void UserAgent::on_invite_final(const InviteContext& context, const sip::Message* response, TimePoint now) {
  const bool ours = call_ && call_->id == context.call_id && call_->invite_branch == context.branch;

  if (response && response->status >= 300) send_ack_for_failure(context, *response);

  if (response && response->status < 300) {
    // Every 2xx must be acknowledged, even for a call this side has already given up on.
    const std::string to(response->header("to").value_or(""));
    const auto contact_header = response->header("contact");
    const std::string target = contact_header ? sip::uri_of(*contact_header) : context.uri;
    Request ack;
    ack.method = "ACK";
    ack.uri = target;
    ack.from = context.from;
    ack.to = to;
    ack.call_id = context.sip_call_id;
    ack.cseq = context.cseq;
    const std::string ack_bytes = build_request(ack, "z9hG4bK" + sip::random_hex(10));
    send_raw(ack_bytes);

    if (!ours) {
      Request bye;
      bye.method = "BYE";
      bye.uri = target;
      bye.from = context.from;
      bye.to = to;
      bye.call_id = context.sip_call_id;
      bye.cseq = context.cseq + 1;
      send_request(bye, now, [](const sip::Message*, TimePoint) {});
      return;
    }
    Call& call = *call_;
    call.ack = ack_bytes;
    call.remote_header = to;
    call.remote_target = target;
    call.state = CallState::Confirmed;
    if (call.cancel_requested) {
      send_bye(now);
      end_call(shutting_down_ ? EndReason::Shutdown : EndReason::Local, 0);
      return;
    }
    const auto answer = sip::parse_audio(response->body);
    if (!answer || !answer->offers_pcma()) {
      send_bye(now);
      end_call(EndReason::MediaFailed, 488);
      return;
    }
    host_.start_media({answer->address, answer->port});
    Event event;
    event.kind = EventKind::CallAnswered;
    event.call_id = call.id;
    event.status = response->status;
    event.remote = call.remote_uri;
    emit(std::move(event));
    return;
  }

  if (!ours) return;
  Call& call = *call_;
  if (!response) {
    end_call(EndReason::Timeout, 408);
    return;
  }
  const int32_t status = response->status;
  if ((status == 401 || status == 407) && !call.authenticated && !call.cancel_requested) {
    if (const auto authorization = authorization_for(*response, "INVITE", call.invite_uri)) {
      call.authenticated = true;
      send_invite(*authorization, now);
      return;
    }
  }
  if (call.cancel_requested) {
    end_call(shutting_down_ ? EndReason::Shutdown : EndReason::Local, status);
  } else {
    end_call(EndReason::Rejected, status);
  }
}

void UserAgent::send_cancel(TimePoint now) {
  Call& call = *call_;
  call.cancel_sent = true;
  Request request;
  request.method = "CANCEL";
  request.uri = call.invite_uri;
  request.from = call.local_header;
  request.to = "<" + call.invite_uri + ">";
  request.call_id = call.sip_call_id;
  request.cseq = call.invite_cseq;
  send_request(request, now, [](const sip::Message*, TimePoint) {}, {}, call.invite_branch);
}

void UserAgent::send_bye(TimePoint now) {
  Call& call = *call_;
  Request request;
  request.method = "BYE";
  request.uri = call.remote_target;
  request.from = call.local_header;
  request.to = call.remote_header;
  request.call_id = call.sip_call_id;
  request.cseq = call.local_cseq++;
  send_request(request, now, [](const sip::Message*, TimePoint) {});
}

// Incoming calls --------------------------------------------------------------------------------

void UserAgent::on_invite_request(const sip::Message& request, TimePoint now) {
  const std::string sip_call_id(request.header("call-id").value_or(""));
  if (call_ && call_->sip_call_id == sip_call_id) {
    if (!call_->outgoing && call_->state != CallState::Confirmed) {
      // A retransmission of the INVITE we are already handling.
      if (!call_->last_response.empty()) send_raw(call_->last_response);
      return;
    }
    // A re-INVITE inside the dialog, e.g. the server moving media. Follow it if it is usable.
    const auto offer = sip::parse_audio(request.body);
    if (request.body.empty() || !offer || !offer->offers_pcma()) {
      send_raw(build_response(request, 488, {}));
      return;
    }
    host_.start_media({offer->address, offer->port});
    send_raw(build_response(request, 200, {}, call_->local_sdp));
    return;
  }

  const std::string tag = sip::random_hex(6);
  if (call_ || shutting_down_) {
    send_raw(build_response(request, 486, tag));
    return;
  }
  const auto offer = sip::parse_audio(request.body);
  if (!offer || !offer->offers_pcma()) {
    send_raw(build_response(request, 488, tag));
    return;
  }

  const std::string from(request.header("from").value_or(""));
  const std::string to(request.header("to").value_or(""));
  Call call;
  call.id = allocate_call_id();
  call.outgoing = false;
  call.state = CallState::Ringing;
  call.sip_call_id = sip_call_id;
  call.local_tag = tag;
  call.local_header = tagged(to, tag);
  call.remote_header = from;
  call.remote_uri = sip::uri_of(from);
  call.remote_display_name = sip::display_name_of(from);
  const auto contact_header = request.header("contact");
  call.remote_target = contact_header ? sip::uri_of(*contact_header) : call.remote_uri;
  call.local_cseq = 1;
  call.invite = request;
  call.offer = *offer;
  if (!config_.correlation_header.empty()) {
    call.correlation_id = std::string(request.header(sip::lowercase(config_.correlation_header)).value_or(""));
  }
  call.last_response = build_response(request, 180, tag);
  send_raw(call.last_response);

  Event event;
  event.kind = EventKind::CallIncoming;
  event.call_id = call.id;
  event.remote = call.remote_uri;
  event.remote_display_name = call.remote_display_name;
  event.correlation_id = call.correlation_id;
  call_ = std::move(call);
  emit(std::move(event));
  (void)now;
}

CommandResult UserAgent::answer(int32_t call_id, TimePoint now) {
  if (!call_ || call_->id != call_id) return CommandResult::NotFound;
  Call& call = *call_;
  if (call.outgoing || call.state != CallState::Ringing) return CommandResult::State;
  const uint16_t port = host_.open_media();
  if (port == 0) {
    send_raw(build_response(*call.invite, 500, call.local_tag));
    end_call(EndReason::MediaFailed, 500);
    return CommandResult::Ok;
  }
  call.media_open = true;
  call.local_sdp = sip::build_audio_sdp(config_.local_address, port, sip::random_u32(), 1);
  call.last_response = build_response(*call.invite, 200, call.local_tag, call.local_sdp);
  call.state = CallState::Answering;
  call.resend_interval = kT1;
  call.resend_at = now + kT1;
  call.ack_deadline = now + kTransactionTimeout;
  send_raw(call.last_response);
  // Start sending right away so the first words are not clipped while the ACK is on its way.
  host_.start_media({call.offer.address, call.offer.port});
  return CommandResult::Ok;
}

CommandResult UserAgent::reject(int32_t call_id, int32_t status, TimePoint) {
  if (status < 400 || status > 699) return CommandResult::InvalidArgument;
  if (!call_ || call_->id != call_id) return CommandResult::NotFound;
  if (call_->outgoing || call_->state != CallState::Ringing) return CommandResult::State;
  send_raw(build_response(*call_->invite, status, call_->local_tag));
  end_call(EndReason::Local, status);
  return CommandResult::Ok;
}

CommandResult UserAgent::hangup(int32_t call_id, TimePoint now) {
  if (!call_ || call_->id != call_id) return CommandResult::NotFound;
  Call& call = *call_;
  const EndReason reason = shutting_down_ ? EndReason::Shutdown : EndReason::Local;
  switch (call.state) {
    case CallState::Calling:
      // CANCEL may only follow a provisional response; otherwise it goes out when one arrives.
      // The call ends when the INVITE gets its final response (normally 487).
      if (!call.cancel_requested) {
        call.cancel_requested = true;
        if (call.provisional) send_cancel(now);
      }
      if (shutting_down_) end_call(reason, 0);
      return CommandResult::Ok;
    case CallState::Ringing:
      send_raw(build_response(*call.invite, 603, call.local_tag));
      end_call(reason, 603);
      return CommandResult::Ok;
    case CallState::Answering:
    case CallState::Confirmed:
      send_bye(now);
      end_call(reason, 0);
      return CommandResult::Ok;
  }
  return CommandResult::State;
}

void UserAgent::end_call(EndReason reason, int32_t status) {
  if (!call_) return;
  if (call_->media_open) host_.close_media();
  Event event;
  event.kind = EventKind::CallEnded;
  event.call_id = call_->id;
  event.status = status;
  event.end_reason = reason;
  event.remote = call_->remote_uri;
  event.remote_display_name = call_->remote_display_name;
  call_.reset();
  emit(std::move(event));
}

void UserAgent::shutdown(TimePoint now) {
  shutting_down_ = true;
  if (call_) hangup(call_->id, now);
  stop_registration(now);
}

// Dispatch -------------------------------------------------------------------------------------

void UserAgent::on_message(std::string_view datagram, TimePoint now) {
  // Keep-alive packets (CRLF) and anything unparseable are dropped silently.
  const auto message = sip::parse_message(datagram);
  if (!message) return;
  if (message->is_response) {
    on_response(*message, now);
  } else {
    on_request(*message, now);
  }
}

void UserAgent::on_response(const sip::Message& response, TimePoint now) {
  const auto cseq = sip::parse_cseq(response.header("cseq").value_or(""));
  if (!cseq) return;
  const auto it = transactions_.find(branch_of(response) + " " + cseq->method);
  if (it == transactions_.end()) {
    // A retransmitted 2xx means our ACK was lost; send it again.
    if (response.status >= 200 && response.status < 300 && cseq->method == "INVITE" && call_ &&
        call_->sip_call_id == response.header("call-id").value_or("") && !call_->ack.empty()) {
      send_raw(call_->ack);
    }
    return;
  }

  if (response.status < 200) {
    Transaction& transaction = it->second;
    if (transaction.method == "INVITE") {
      transaction.retransmitting = false;
      transaction.deadline = now + kInviteAfterProvisional;
    } else {
      transaction.interval = kT2;
    }
    if (transaction.on_provisional) transaction.on_provisional(response, now);
    return;
  }

  Transaction transaction = std::move(it->second);
  transactions_.erase(it);
  if (transaction.on_final) transaction.on_final(&response, now);
}

void UserAgent::on_request(const sip::Message& request, TimePoint now) {
  if (request.method == "ACK") {
    if (call_ && !call_->outgoing && call_->state == CallState::Answering &&
        call_->sip_call_id == request.header("call-id").value_or("")) {
      call_->state = CallState::Confirmed;
      Event event;
      event.kind = EventKind::CallAnswered;
      event.call_id = call_->id;
      event.status = 200;
      event.remote = call_->remote_uri;
      event.remote_display_name = call_->remote_display_name;
      event.correlation_id = call_->correlation_id;
      emit(std::move(event));
    }
    return;
  }
  if (!request.header("via") || !request.header("from") || !request.header("to") || !request.header("call-id") ||
      !sip::parse_cseq(request.header("cseq").value_or(""))) {
    send_raw(build_response(request, 400, {}));
    return;
  }

  const bool same_call = call_ && call_->sip_call_id == request.header("call-id").value_or("");
  if (request.method == "INVITE") {
    on_invite_request(request, now);
  } else if (request.method == "OPTIONS") {
    send_raw(build_response(request, 200, sip::random_hex(6)));
  } else if (request.method == "BYE") {
    if (!same_call) {
      send_raw(build_response(request, 481, {}));
      return;
    }
    send_raw(build_response(request, 200, {}));
    end_call(EndReason::RemoteHangup, 0);
  } else if (request.method == "CANCEL") {
    if (!same_call || call_->outgoing) {
      send_raw(build_response(request, 481, {}));
      return;
    }
    send_raw(build_response(request, 200, call_->local_tag));
    if (call_->state == CallState::Ringing) {
      send_raw(build_response(*call_->invite, 487, call_->local_tag));
      end_call(EndReason::RemoteCancelled, 487);
    }
  } else {
    send_raw(build_response(request, 501, {}));
  }
}

void UserAgent::on_timer(TimePoint now) {
  std::vector<std::string> expired;
  for (auto& [key, transaction] : transactions_) {
    if (now >= transaction.deadline) {
      expired.push_back(key);
    } else if (transaction.retransmitting && now >= transaction.retransmit_at) {
      send_raw(transaction.bytes);
      transaction.interval = transaction.method == "INVITE" ? transaction.interval * 2
                                                            : std::min<Duration>(transaction.interval * 2, kT2);
      transaction.retransmit_at = now + transaction.interval;
    }
  }
  for (const auto& key : expired) {
    const auto it = transactions_.find(key);
    if (it == transactions_.end()) continue;
    Transaction transaction = std::move(it->second);
    transactions_.erase(it);
    if (transaction.on_final) transaction.on_final(nullptr, now);
  }

  if (call_ && call_->state == CallState::Answering) {
    if (now >= call_->ack_deadline) {
      send_bye(now);
      end_call(EndReason::Timeout, 408);
    } else if (now >= call_->resend_at) {
      send_raw(call_->last_response);
      call_->resend_interval = std::min<Duration>(call_->resend_interval * 2, kT2);
      call_->resend_at = now + call_->resend_interval;
    }
  }

  if (registration_.wanted && registration_.next_attempt && now >= *registration_.next_attempt &&
      !registration_.in_flight) {
    registration_.next_attempt.reset();
    send_register(config_.register_expires, {}, now);
  }
}

std::optional<TimePoint> UserAgent::next_deadline() const {
  std::optional<TimePoint> next;
  const auto consider = [&next](TimePoint at) {
    if (!next || at < *next) next = at;
  };
  for (const auto& [key, transaction] : transactions_) {
    consider(transaction.deadline);
    if (transaction.retransmitting) consider(transaction.retransmit_at);
  }
  if (call_ && call_->state == CallState::Answering) {
    consider(call_->resend_at);
    consider(call_->ack_deadline);
  }
  if (registration_.wanted && registration_.next_attempt) consider(*registration_.next_attempt);
  return next;
}

}  // namespace ketphone::core
