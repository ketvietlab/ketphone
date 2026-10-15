#include "sip/base64.hpp"

namespace ketphone::sip {
namespace {

constexpr char kAlphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

int value_of(char c) {
  if (c >= 'A' && c <= 'Z') return c - 'A';
  if (c >= 'a' && c <= 'z') return c - 'a' + 26;
  if (c >= '0' && c <= '9') return c - '0' + 52;
  if (c == '+') return 62;
  if (c == '/') return 63;
  return -1;
}

}  // namespace

std::string base64_encode(std::span<const uint8_t> data) {
  std::string out;
  out.reserve((data.size() + 2) / 3 * 4);
  size_t i = 0;
  for (; i + 3 <= data.size(); i += 3) {
    const uint32_t triple = (uint32_t{data[i]} << 16) | (uint32_t{data[i + 1]} << 8) | data[i + 2];
    out.push_back(kAlphabet[(triple >> 18) & 63]);
    out.push_back(kAlphabet[(triple >> 12) & 63]);
    out.push_back(kAlphabet[(triple >> 6) & 63]);
    out.push_back(kAlphabet[triple & 63]);
  }
  const size_t rest = data.size() - i;
  if (rest > 0) {
    uint32_t triple = uint32_t{data[i]} << 16;
    if (rest == 2) triple |= uint32_t{data[i + 1]} << 8;
    out.push_back(kAlphabet[(triple >> 18) & 63]);
    out.push_back(kAlphabet[(triple >> 12) & 63]);
    out.push_back(rest == 2 ? kAlphabet[(triple >> 6) & 63] : '=');
    out.push_back('=');
  }
  return out;
}

std::optional<std::vector<uint8_t>> base64_decode(std::string_view text) {
  size_t padding = 0;
  while (!text.empty() && text.back() == '=') {
    text.remove_suffix(1);
    ++padding;
  }
  // Padding, when present, completes the last group of four and is never more than two.
  if (text.size() % 4 == 1 || padding > 2 || (padding > 0 && (text.size() + padding) % 4 != 0)) return std::nullopt;
  std::vector<uint8_t> out;
  out.reserve(text.size() * 3 / 4);
  uint32_t accumulator = 0;
  int bits = 0;
  for (const char c : text) {
    const int value = value_of(c);
    if (value < 0) return std::nullopt;
    accumulator = (accumulator << 6) | static_cast<uint32_t>(value);
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out.push_back(static_cast<uint8_t>((accumulator >> bits) & 0xff));
    }
  }
  // Leftover bits must be the zero padding of the last character.
  if ((accumulator & ((1u << bits) - 1)) != 0) return std::nullopt;
  return out;
}

}  // namespace ketphone::sip
