#pragma once

#include <cstddef>
#include <optional>
#include <string>
#include <string_view>

namespace ketphone::sip {

// Cuts SIP messages out of a byte stream (TCP or TLS), where Content-Length marks where each
// message ends (RFC 3261 section 18.3). CRLFs between messages, which are keep-alive pings and pongs
// (RFC 5626 section 3.5.1), are skipped.
class StreamFramer {
 public:
  // Larger messages mean a broken or hostile peer; a call's signalling stays far below this.
  static constexpr size_t kMaxMessage = 65536;

  void push(std::string_view bytes);

  // The next complete message, or nothing until more bytes arrive. After a framing error (no
  // Content-Length, or a message over kMaxMessage) it returns nothing for good and failed() is set;
  // the connection must then be closed.
  std::optional<std::string> next();

  bool failed() const { return failed_; }
  void reset();

 private:
  std::string buffer_;
  bool failed_ = false;
};

}  // namespace ketphone::sip
