#include "media/srtp.hpp"

#include <srtp.h>

#include <cstring>
#include <limits>
#include <mutex>

#include "sip/random.hpp"

namespace ketphone::media {

static_assert(kSrtpTrailerRoom == SRTP_MAX_TRAILER_LEN);
static_assert(kSrtpKeyLength == SRTP_AES_ICM_128_KEY_LEN_WSALT);

namespace {

bool initialize() {
  static std::once_flag once;
  static bool ready = false;
  std::call_once(once, [] { ready = srtp_init() == srtp_err_status_ok; });
  return ready;
}

bool fits(std::span<uint8_t> buffer, size_t size, size_t room) {
  return reinterpret_cast<uintptr_t>(buffer.data()) % 4 == 0 && size <= buffer.size() &&
         buffer.size() - size >= room && size <= static_cast<size_t>(std::numeric_limits<int>::max());
}

}  // namespace

struct SrtpStream::Session {
  srtp_t handle = nullptr;
  ~Session() {
    if (handle != nullptr) srtp_dealloc(handle);
  }
};

std::optional<SrtpKey> generate_srtp_key() {
  SrtpKey key{};
  if (!sip::secure_random(key)) return std::nullopt;
  return key;
}

std::unique_ptr<SrtpStream> SrtpStream::create(Direction direction, const SrtpKey& key) {
  if (!initialize()) return nullptr;
  // libsrtp reads the key through a non-const pointer while creating the session; give it a copy.
  SrtpKey material = key;
  srtp_policy_t policy;
  std::memset(&policy, 0, sizeof(policy));
  srtp_crypto_policy_set_aes_cm_128_hmac_sha1_80(&policy.rtp);
  srtp_crypto_policy_set_aes_cm_128_hmac_sha1_80(&policy.rtcp);
  policy.ssrc.type = direction == Direction::Outbound ? ssrc_any_outbound : ssrc_any_inbound;
  policy.key = material.data();
  policy.window_size = 0;  // libsrtp's default replay window of 128 packets
  policy.allow_repeat_tx = 0;
  auto session = std::make_unique<Session>();
  const srtp_err_status_t status = srtp_create(&session->handle, &policy);
  material.fill(0);
  if (status != srtp_err_status_ok) {
    session->handle = nullptr;
    return nullptr;
  }
  return std::unique_ptr<SrtpStream>(new SrtpStream(std::move(session), key));
}

SrtpStream::SrtpStream(std::unique_ptr<Session> session, const SrtpKey& key)
    : session_(std::move(session)), key_(key) {}

SrtpStream::~SrtpStream() { key_.fill(0); }

size_t SrtpStream::protect(std::span<uint8_t> buffer, size_t size) {
  if (!fits(buffer, size, kSrtpTrailerRoom)) return 0;
  int length = static_cast<int>(size);
  if (srtp_protect(session_->handle, buffer.data(), &length) != srtp_err_status_ok || length < 0) return 0;
  return static_cast<size_t>(length);
}

std::optional<size_t> SrtpStream::unprotect(std::span<uint8_t> buffer, size_t size) {
  // Shorter than an RTP header plus the tag cannot be SRTP; libsrtp checks too, but say so here.
  if (size < 12 + 10 || !fits(buffer, size, 0)) return std::nullopt;
  int length = static_cast<int>(size);
  if (srtp_unprotect(session_->handle, buffer.data(), &length) != srtp_err_status_ok || length < 0) {
    return std::nullopt;
  }
  return static_cast<size_t>(length);
}

}  // namespace ketphone::media
