#include "sip/stream_framer.hpp"

#include "sip/text.hpp"

namespace ketphone::sip {
namespace {

// Content-Length (or its compact form "l") from a message head, or nothing if absent or invalid.
std::optional<size_t> content_length(std::string_view head) {
  bool first = true;
  for (const std::string_view line : split_lines(head)) {
    if (first) {
      first = false;  // the start line
      continue;
    }
    const size_t colon = line.find(':');
    if (colon == std::string_view::npos) continue;
    const std::string name = lowercase(trim(line.substr(0, colon)));
    if (name == "content-length" || name == "l") return parse_integer<size_t>(line.substr(colon + 1));
  }
  return std::nullopt;
}

}  // namespace

void StreamFramer::push(std::string_view bytes) {
  if (failed_) return;
  buffer_.append(bytes);
}

std::optional<std::string> StreamFramer::next() {
  if (failed_) return std::nullopt;
  const size_t start = buffer_.find_first_not_of("\r\n");
  if (start == std::string::npos) {
    buffer_.clear();
    return std::nullopt;
  }
  if (start > 0) buffer_.erase(0, start);

  const size_t head_end = buffer_.find("\r\n\r\n");
  if (head_end == std::string::npos) {
    if (buffer_.size() > kMaxMessage) failed_ = true;
    return std::nullopt;
  }
  const auto length = content_length(std::string_view(buffer_).substr(0, head_end));
  const size_t total = head_end + 4 + length.value_or(0);
  if (!length || total > kMaxMessage) {
    failed_ = true;
    return std::nullopt;
  }
  if (buffer_.size() < total) return std::nullopt;
  std::string message = buffer_.substr(0, total);
  buffer_.erase(0, total);
  return message;
}

void StreamFramer::reset() {
  buffer_.clear();
  failed_ = false;
}

}  // namespace ketphone::sip
