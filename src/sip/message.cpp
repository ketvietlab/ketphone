#include "sip/message.hpp"

#include "sip/text.hpp"

namespace ketphone::sip {
namespace {

std::string full_header_name(std::string_view raw) {
  std::string name = lowercase(trim(raw));
  if (name.size() != 1) return name;
  switch (name[0]) {
    case 'v': return "via";
    case 'f': return "from";
    case 't': return "to";
    case 'i': return "call-id";
    case 'm': return "contact";
    case 'l': return "content-length";
    case 'c': return "content-type";
    case 'k': return "supported";
    case 's': return "subject";
    case 'e': return "content-encoding";
    default: return name;
  }
}

bool is_token(std::string_view value) {
  if (value.empty()) return false;
  for (char c : value) {
    if (!std::isalnum(static_cast<unsigned char>(c)) && std::string_view("-.!%*_+`'~").find(c) == std::string_view::npos) {
      return false;
    }
  }
  return true;
}

}  // namespace

std::optional<std::string_view> Message::header(std::string_view name) const {
  for (const auto& [key, value] : headers) {
    if (key == name) return value;
  }
  return std::nullopt;
}

std::vector<std::string_view> Message::header_all(std::string_view name) const {
  std::vector<std::string_view> values;
  for (const auto& [key, value] : headers) {
    if (key == name) values.emplace_back(value);
  }
  return values;
}

std::optional<Message> parse_message(std::string_view datagram) {
  size_t split = datagram.find("\r\n\r\n");
  size_t separator = 4;
  if (split == std::string_view::npos) {
    split = datagram.find("\n\n");
    separator = 2;
  }
  const std::string_view head = split == std::string_view::npos ? datagram : datagram.substr(0, split);
  std::string_view body = split == std::string_view::npos ? std::string_view{} : datagram.substr(split + separator);

  const auto lines = split_lines(head);
  if (lines.empty()) return std::nullopt;

  Message message;
  const std::string_view start = lines[0];
  if (start.starts_with("SIP/2.0 ")) {
    if (start.size() < 11) return std::nullopt;
    const auto status = parse_integer<int>(start.substr(8, 3));
    if (!status || *status < 100 || *status > 699) return std::nullopt;
    message.is_response = true;
    message.status = *status;
    message.reason = std::string(trim(start.substr(11)));
  } else {
    const size_t first = start.find(' ');
    const size_t last = start.rfind(' ');
    if (first == std::string_view::npos || last == first || start.substr(last + 1) != "SIP/2.0") return std::nullopt;
    message.method = std::string(start.substr(0, first));
    message.uri = std::string(trim(start.substr(first + 1, last - first - 1)));
    if (!is_token(message.method) || message.uri.empty()) return std::nullopt;
  }

  for (size_t i = 1; i < lines.size(); ++i) {
    const std::string_view line = lines[i];
    if (line.empty()) continue;
    if ((line.front() == ' ' || line.front() == '\t') && !message.headers.empty()) {
      auto& value = message.headers.back().second;
      value += ' ';
      value += trim(line);
      continue;
    }
    const size_t colon = line.find(':');
    if (colon == std::string_view::npos || colon == 0) return std::nullopt;
    message.headers.emplace_back(full_header_name(line.substr(0, colon)), std::string(trim(line.substr(colon + 1))));
  }

  if (const auto length = message.header("content-length")) {
    const auto size = parse_integer<size_t>(*length);
    if (!size || *size > body.size()) return std::nullopt;
    body = body.substr(0, *size);
  }
  message.body = std::string(body);
  return message;
}

std::optional<CSeq> parse_cseq(std::string_view value) {
  value = trim(value);
  const size_t space = value.find_first_of(" \t");
  if (space == std::string_view::npos) return std::nullopt;
  const auto number = parse_integer<uint32_t>(value.substr(0, space));
  const std::string_view method = trim(value.substr(space));
  if (!number || method.empty()) return std::nullopt;
  return CSeq{*number, std::string(method)};
}

std::string uri_of(std::string_view name_addr) {
  const size_t open = name_addr.find('<');
  if (open != std::string_view::npos) {
    const size_t close = name_addr.find('>', open);
    if (close != std::string_view::npos) return std::string(trim(name_addr.substr(open + 1, close - open - 1)));
  }
  return std::string(trim(name_addr.substr(0, name_addr.find(';'))));
}

std::string display_name_of(std::string_view name_addr) {
  const size_t open = name_addr.find('<');
  if (open == std::string_view::npos) return {};
  std::string_view name = trim(name_addr.substr(0, open));
  if (name.size() >= 2 && name.front() == '"' && name.back() == '"') {
    std::string out;
    for (size_t i = 1; i + 1 < name.size(); ++i) {
      if (name[i] == '\\' && i + 2 < name.size()) ++i;
      out.push_back(name[i]);
    }
    return out;
  }
  return std::string(name);
}

std::optional<std::string> param_of(std::string_view value, std::string_view name) {
  // Parameters inside <...> belong to the URI, not to the header.
  const size_t close = value.find('>');
  if (close != std::string_view::npos) value = value.substr(close + 1);
  size_t position = 0;
  while ((position = value.find(';', position)) != std::string_view::npos) {
    ++position;
    const size_t end = value.find_first_of(";,", position);
    const std::string_view param = value.substr(position, end == std::string_view::npos ? std::string_view::npos : end - position);
    const size_t equals = param.find('=');
    const std::string_view key = trim(param.substr(0, equals));
    if (iequals(key, name)) {
      if (equals == std::string_view::npos) return std::string{};
      std::string_view raw = trim(param.substr(equals + 1));
      if (raw.size() >= 2 && raw.front() == '"' && raw.back() == '"') raw = raw.substr(1, raw.size() - 2);
      return std::string(raw);
    }
  }
  return std::nullopt;
}

std::string user_of(std::string_view uri) {
  const size_t colon = uri.find(':');
  if (colon != std::string_view::npos) uri.remove_prefix(colon + 1);
  const size_t at = uri.find('@');
  if (at == std::string_view::npos) return {};
  return std::string(uri.substr(0, at));
}

MessageBuilder::MessageBuilder(std::string start_line) : start_line_(std::move(start_line)) {}

MessageBuilder& MessageBuilder::add(std::string_view name, std::string_view value) {
  headers_.emplace_back(name, value);
  return *this;
}

MessageBuilder& MessageBuilder::body(std::string content_type, std::string body) {
  content_type_ = std::move(content_type);
  body_ = std::move(body);
  return *this;
}

std::string MessageBuilder::build() const {
  std::string out = start_line_ + "\r\n";
  for (const auto& [name, value] : headers_) out += name + ": " + value + "\r\n";
  if (!body_.empty()) out += "Content-Type: " + content_type_ + "\r\n";
  out += "Content-Length: " + std::to_string(body_.size()) + "\r\n\r\n";
  out += body_;
  return out;
}

std::string_view reason_phrase(int status) {
  switch (status) {
    case 100: return "Trying";
    case 180: return "Ringing";
    case 183: return "Session Progress";
    case 200: return "OK";
    case 400: return "Bad Request";
    case 408: return "Request Timeout";
    case 480: return "Temporarily Unavailable";
    case 481: return "Call/Transaction Does Not Exist";
    case 486: return "Busy Here";
    case 487: return "Request Terminated";
    case 488: return "Not Acceptable Here";
    case 500: return "Server Internal Error";
    case 501: return "Not Implemented";
    case 603: return "Decline";
    default: return status < 300 ? "OK" : "Error";
  }
}

}  // namespace ketphone::sip
