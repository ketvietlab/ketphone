#include <string>
#include <vector>

#include "check.hpp"
#include "sip/base64.hpp"

using namespace ketphone::sip;

namespace {
std::vector<uint8_t> bytes(std::string_view text) { return {text.begin(), text.end()}; }
}  // namespace

TEST(base64_matches_the_rfc_4648_vectors) {
  const std::pair<const char*, const char*> vectors[] = {
      {"", ""},         {"f", "Zg=="},         {"fo", "Zm8="},         {"foo", "Zm9v"},
      {"foob", "Zm9vYg=="}, {"fooba", "Zm9vYmE="}, {"foobar", "Zm9vYmFy"},
  };
  for (const auto& [plain, encoded] : vectors) {
    CHECK_EQ(base64_encode(bytes(plain)), std::string(encoded));
    const auto decoded = base64_decode(encoded);
    CHECK(decoded.has_value());
    CHECK(*decoded == bytes(plain));
  }
}

TEST(base64_round_trips_every_byte_and_accepts_missing_padding) {
  std::vector<uint8_t> all(256);
  for (size_t n = 0; n < all.size(); ++n) all[n] = static_cast<uint8_t>(n);
  const auto decoded = base64_decode(base64_encode(all));
  CHECK(decoded.has_value());
  CHECK(*decoded == all);
  CHECK(base64_decode("Zm9vYg").has_value());
  CHECK(*base64_decode("Zm9vYg") == bytes("foob"));
}

TEST(base64_refuses_text_that_encoding_cannot_produce) {
  CHECK(!base64_decode("Zm9v!").has_value());   // outside the alphabet
  CHECK(!base64_decode("Zm9v Yg==").has_value());  // whitespace is the caller's to strip
  CHECK(!base64_decode("Z").has_value());       // one character carries less than a byte
  CHECK(!base64_decode("Zm9=v").has_value());   // data after padding
  CHECK(!base64_decode("Zh==").has_value());    // leftover bits must be zero
  CHECK(!base64_decode("Zm9vYg===").has_value());
}
