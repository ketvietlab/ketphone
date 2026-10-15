#include <string>

#include "check.hpp"
#include "sip/stream_framer.hpp"

using namespace ketphone::sip;

namespace {
const std::string kOptions =
    "OPTIONS sip:1001@example.test SIP/2.0\r\nCall-ID: a\r\nContent-Length: 0\r\n\r\n";
const std::string kWithBody =
    "MESSAGE sip:1001@example.test SIP/2.0\r\nCall-ID: b\r\nl: 5\r\n\r\nhello";
}  // namespace

TEST(stream_framer_cuts_messages_at_content_length_across_reads) {
  StreamFramer framer;
  const std::string stream = kOptions + kWithBody + kOptions;
  // One byte at a time: every split point inside a head or body must wait for the rest.
  int found = 0;
  for (const char byte : stream) {
    framer.push(std::string_view(&byte, 1));
    while (auto message = framer.next()) {
      CHECK_EQ(*message, found == 1 ? kWithBody : kOptions);
      ++found;
    }
  }
  CHECK_EQ(found, 3);
  CHECK(!framer.failed());
}

TEST(stream_framer_skips_keep_alive_crlfs_between_messages) {
  StreamFramer framer;
  framer.push("\r\n\r\n");
  CHECK(!framer.next().has_value());
  framer.push("\r\n" + kOptions + "\r\n\r\n" + kWithBody);
  CHECK_EQ(*framer.next(), kOptions);
  CHECK_EQ(*framer.next(), kWithBody);
  CHECK(!framer.next().has_value());
  CHECK(!framer.failed());
}

TEST(stream_framer_fails_without_content_length_or_when_too_large) {
  StreamFramer missing;
  missing.push("OPTIONS sip:a SIP/2.0\r\nCall-ID: a\r\n\r\n");
  CHECK(!missing.next().has_value());
  CHECK(missing.failed());
  missing.push(kOptions);
  CHECK(!missing.next().has_value());  // stays failed until reset
  missing.reset();
  missing.push(kOptions);
  CHECK_EQ(*missing.next(), kOptions);

  StreamFramer large;
  large.push("MESSAGE sip:a SIP/2.0\r\nContent-Length: 70000\r\n\r\n");
  CHECK(!large.next().has_value());
  CHECK(large.failed());

  StreamFramer endless;
  endless.push(std::string(StreamFramer::kMaxMessage + 1, 'x'));
  CHECK(!endless.next().has_value());
  CHECK(endless.failed());
}
