#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>

namespace ketphone::media {

// SRTP master key (16 bytes) followed by its master salt (14 bytes): the inline key of an
// AES_CM_128_HMAC_SHA1_80 SDES crypto line.
inline constexpr size_t kSrtpKeyLength = 30;
using SrtpKey = std::array<uint8_t, kSrtpKeyLength>;

// Room that protect() may write past the end of the RTP packet (libsrtp's SRTP_MAX_TRAILER_LEN).
// The authentication tag itself is 10 bytes.
inline constexpr size_t kSrtpTrailerRoom = 144;

// A fresh key and salt from the system's cryptographic generator, or nothing if it failed.
std::optional<SrtpKey> generate_srtp_key();

// One direction of a call's SRTP (RFC 3711, AES_CM_128_HMAC_SHA1_80): protects what this side sends
// with its own key, or authenticates and decrypts what the far end sends with the key it announced.
// Any SSRC is accepted, so a far end that switches source (Asterisk re-bridging) keeps working, and
// replayed packets are refused. Used on one thread at a time.
class SrtpStream {
 public:
  enum class Direction { Outbound, Inbound };

  // Nothing when libsrtp refuses the key.
  static std::unique_ptr<SrtpStream> create(Direction direction, const SrtpKey& key);
  ~SrtpStream();
  SrtpStream(const SrtpStream&) = delete;
  SrtpStream& operator=(const SrtpStream&) = delete;

  const SrtpKey& key() const { return key_; }

  // Encrypts the RTP packet in the first `size` bytes of `buffer` and appends its tag, in place.
  // `buffer` must start on a 4-byte boundary and have kSrtpTrailerRoom bytes after the packet.
  // Returns the SRTP packet's size, or 0 on failure.
  size_t protect(std::span<uint8_t> buffer, size_t size);

  // Verifies and decrypts the SRTP packet in the first `size` bytes of `buffer`, in place, with the
  // same alignment requirement. Returns the RTP packet's size, or nothing when the packet fails
  // authentication, repeats an earlier one or is not SRTP at all.
  std::optional<size_t> unprotect(std::span<uint8_t> buffer, size_t size);

 private:
  struct Session;
  SrtpStream(std::unique_ptr<Session> session, const SrtpKey& key);
  std::unique_ptr<Session> session_;
  SrtpKey key_;
};

}  // namespace ketphone::media
