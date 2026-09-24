#pragma once

#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace ketphone::sip {

// A parsed SIP request or response. Header names are stored lowercase with compact forms
// expanded ("v" becomes "via"), in their original order, so repeated headers such as Via keep
// their sequence.
struct Message {
  bool is_response = false;
  int status = 0;
  std::string reason;
  std::string method;
  std::string uri;
  std::vector<std::pair<std::string, std::string>> headers;
  std::string body;

  // First value of a header, by lowercase full name.
  std::optional<std::string_view> header(std::string_view name) const;
  std::vector<std::string_view> header_all(std::string_view name) const;
};

// Returns nothing when the datagram is not a well-formed SIP message.
std::optional<Message> parse_message(std::string_view datagram);

struct CSeq {
  uint32_t number = 0;
  std::string method;
};
std::optional<CSeq> parse_cseq(std::string_view value);

// The URI inside a name-addr ("Lan" <sip:1001@ketviet>;tag=x gives sip:1001@ketviet), or the
// part before the first ';' for an addr-spec.
std::string uri_of(std::string_view name_addr);

// The quoted or bare display name before the URI, or "" when there is none.
std::string display_name_of(std::string_view name_addr);

// Value of a ;name=value parameter outside the angle brackets (e.g. tag, expires, branch).
std::optional<std::string> param_of(std::string_view value, std::string_view name);

// The user part of a SIP URI: sip:1001@ketviet gives 1001.
std::string user_of(std::string_view uri);

// Builds a message: start line, headers in order, Content-Length, blank line, body.
class MessageBuilder {
 public:
  explicit MessageBuilder(std::string start_line);
  MessageBuilder& add(std::string_view name, std::string_view value);
  MessageBuilder& body(std::string content_type, std::string body);
  std::string build() const;

 private:
  std::string start_line_;
  std::vector<std::pair<std::string, std::string>> headers_;
  std::string content_type_;
  std::string body_;
};

std::string_view reason_phrase(int status);

}  // namespace ketphone::sip
