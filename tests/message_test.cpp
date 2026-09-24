#include "check.hpp"
#include "sip/message.hpp"

using namespace ketphone::sip;

TEST(parses_a_response_with_compact_and_folded_headers) {
  const std::string text =
      "SIP/2.0 401 Unauthorized\r\n"
      "v: SIP/2.0/UDP 10.0.0.2:5060;branch=z9hG4bKabc;rport=5060\r\n"
      "f: <sip:1001@ketviet>;tag=aa\r\n"
      "t: <sip:1001@ketviet>;tag=bb\r\n"
      "i: call-1\r\n"
      "CSeq: 7 REGISTER\r\n"
      "WWW-Authenticate: Digest realm=\"ketviet\",\r\n"
      "  nonce=\"n\"\r\n"
      "l: 0\r\n\r\n";
  const auto message = parse_message(text);
  CHECK(message.has_value());
  CHECK(message->is_response);
  CHECK_EQ(message->status, 401);
  CHECK_EQ(message->reason, std::string("Unauthorized"));
  CHECK_EQ(std::string(*message->header("call-id")), std::string("call-1"));
  CHECK_EQ(std::string(*message->header("www-authenticate")), std::string("Digest realm=\"ketviet\", nonce=\"n\""));
  const auto cseq = parse_cseq(*message->header("cseq"));
  CHECK(cseq.has_value());
  CHECK_EQ(cseq->number, 7u);
  CHECK_EQ(cseq->method, std::string("REGISTER"));
}

TEST(parses_a_request_and_trims_the_body_to_content_length) {
  const std::string text =
      "INVITE sip:1001@10.0.0.2:5060 SIP/2.0\r\n"
      "Via: SIP/2.0/UDP 172.29.73.10:5060;branch=z9hG4bK1\r\n"
      "Via: SIP/2.0/UDP 172.29.73.11:5060;branch=z9hG4bK2\r\n"
      "Content-Length: 4\r\n\r\n"
      "v=0\r\ntrailing";
  const auto message = parse_message(text);
  CHECK(message.has_value());
  CHECK(!message->is_response);
  CHECK_EQ(message->method, std::string("INVITE"));
  CHECK_EQ(message->uri, std::string("sip:1001@10.0.0.2:5060"));
  CHECK_EQ(message->header_all("via").size(), size_t{2});
  CHECK_EQ(message->body, std::string("v=0\r"));
}

TEST(rejects_garbage_and_truncated_bodies) {
  CHECK(!parse_message("\r\n\r\n").has_value());
  CHECK(!parse_message("hello world").has_value());
  CHECK(!parse_message("SIP/2.0 99 Nope\r\n\r\n").has_value());
  CHECK(!parse_message("OPTIONS sip:x SIP/2.0\r\nContent-Length: 10\r\n\r\nshort").has_value());
  CHECK(!parse_message("OPTIONS sip:x SIP/2.0\r\nno colon here\r\n\r\n").has_value());
}

TEST(name_addr_helpers_extract_uri_display_name_and_params) {
  const std::string from = "\"Nguy\xE1\xBB\x85n \\\"Lan\\\"\" <sip:1001@ketviet;transport=udp>;tag=abc;expires=60";
  CHECK_EQ(uri_of(from), std::string("sip:1001@ketviet;transport=udp"));
  CHECK_EQ(display_name_of(from), std::string("Nguy\xE1\xBB\x85n \"Lan\""));
  CHECK_EQ(*param_of(from, "tag"), std::string("abc"));
  CHECK_EQ(*param_of(from, "expires"), std::string("60"));
  // transport= is inside the brackets, so it is a URI parameter, not a header parameter.
  CHECK(!param_of(from, "transport").has_value());
  CHECK_EQ(uri_of("sip:1002@ketviet;tag=x"), std::string("sip:1002@ketviet"));
  CHECK_EQ(display_name_of("<sip:1002@ketviet>"), std::string(""));
  CHECK_EQ(user_of("sip:*43@127.0.0.1"), std::string("*43"));
}

TEST(builder_writes_content_length_and_type) {
  const std::string built = MessageBuilder("OPTIONS sip:x SIP/2.0").add("Call-ID", "c").body("application/sdp", "v=0\r\n").build();
  CHECK_EQ(built, std::string("OPTIONS sip:x SIP/2.0\r\nCall-ID: c\r\nContent-Type: application/sdp\r\n"
                              "Content-Length: 5\r\n\r\nv=0\r\n"));
  const auto parsed = parse_message(built);
  CHECK(parsed.has_value());
  CHECK_EQ(parsed->body, std::string("v=0\r\n"));
}
