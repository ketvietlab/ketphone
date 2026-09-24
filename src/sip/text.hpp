#pragma once

#include <cctype>
#include <charconv>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace ketphone::sip {

inline std::string_view trim(std::string_view value) {
  while (!value.empty() && (value.front() == ' ' || value.front() == '\t')) value.remove_prefix(1);
  while (!value.empty() && (value.back() == ' ' || value.back() == '\t' || value.back() == '\r')) {
    value.remove_suffix(1);
  }
  return value;
}

inline std::string lowercase(std::string_view value) {
  std::string out(value);
  for (char& c : out) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
  return out;
}

inline bool iequals(std::string_view a, std::string_view b) {
  if (a.size() != b.size()) return false;
  for (size_t i = 0; i < a.size(); ++i) {
    if (std::tolower(static_cast<unsigned char>(a[i])) != std::tolower(static_cast<unsigned char>(b[i]))) {
      return false;
    }
  }
  return true;
}

// Splits on CRLF, also accepting bare LF.
inline std::vector<std::string_view> split_lines(std::string_view text) {
  std::vector<std::string_view> lines;
  while (!text.empty()) {
    const size_t end = text.find('\n');
    std::string_view line = end == std::string_view::npos ? text : text.substr(0, end);
    if (!line.empty() && line.back() == '\r') line.remove_suffix(1);
    lines.push_back(line);
    if (end == std::string_view::npos) break;
    text.remove_prefix(end + 1);
  }
  return lines;
}

template <typename Integer>
std::optional<Integer> parse_integer(std::string_view text) {
  text = trim(text);
  Integer value{};
  const auto [end, error] = std::from_chars(text.data(), text.data() + text.size(), value);
  if (error != std::errc{} || end != text.data() + text.size()) return std::nullopt;
  return value;
}

}  // namespace ketphone::sip
