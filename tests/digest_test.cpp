#include "check.hpp"
#include "sip/digest.hpp"
#include "sip/md5.hpp"

using namespace ketphone::sip;

// RFC 1321 appendix A.5 test suite.
TEST(md5_matches_rfc1321_vectors) {
  CHECK_EQ(md5_hex(""), std::string("d41d8cd98f00b204e9800998ecf8427e"));
  CHECK_EQ(md5_hex("a"), std::string("0cc175b9c0f1b6a831c399e269772661"));
  CHECK_EQ(md5_hex("abc"), std::string("900150983cd24fb0d6963f7d28e17f72"));
  CHECK_EQ(md5_hex("message digest"), std::string("f96b697d7cb7938d525a2f31aaf161d0"));
  CHECK_EQ(md5_hex("abcdefghijklmnopqrstuvwxyz"), std::string("c3fcd3d76192e4007dfb496cca67e13b"));
  CHECK_EQ(md5_hex("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"),
           std::string("d174ab98d277d9f5a5611c2c9f419d9f"));
  CHECK_EQ(md5_hex("12345678901234567890123456789012345678901234567890123456789012345678901234567890"),
           std::string("57edf4a22be3c955ac49da2e2107b67a"));
}

// Lengths around the 56-byte padding boundary take the two-block tail.
TEST(md5_handles_padding_boundaries) {
  CHECK_EQ(md5_hex(std::string(55, 'a')), std::string("ef1772b6dff9a122358552954ad0df65"));
  CHECK_EQ(md5_hex(std::string(56, 'a')), std::string("3b0c8ac703f828b04c6c197006d17218"));
  CHECK_EQ(md5_hex(std::string(64, 'a')), std::string("014842d480b571495a4a0363793f7367"));
}

// RFC 2617 section 3.5.
TEST(digest_response_matches_rfc2617_example) {
  const auto challenge = parse_challenge(
      "Digest realm=\"testrealm@host.com\", qop=\"auth,auth-int\", "
      "nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\", opaque=\"5ccc069c403ebaf9f0171e9517f40e41\"");
  CHECK(challenge.has_value());
  CHECK_EQ(challenge->realm, std::string("testrealm@host.com"));
  CHECK(challenge->qop_auth);
  CHECK_EQ(challenge->opaque, std::string("5ccc069c403ebaf9f0171e9517f40e41"));
  const Credentials credentials{"Mufasa", "Circle Of Life"};
  CHECK_EQ(digest_response(credentials, *challenge, "GET", "/dir/index.html", "00000001", "0a4f113b"),
           std::string("6629fae49393a05397450978507c4ef1"));
}

TEST(digest_without_qop_uses_the_rfc2069_form) {
  Challenge challenge;
  challenge.realm = "ketviet";
  challenge.nonce = "abc";
  const Credentials credentials{"1001", "secret"};
  const std::string ha1 = md5_hex("1001:ketviet:secret");
  const std::string ha2 = md5_hex("REGISTER:sip:127.0.0.1");
  CHECK_EQ(digest_response(credentials, challenge, "REGISTER", "sip:127.0.0.1", "", ""),
           md5_hex(ha1 + ":abc:" + ha2));
}

TEST(authorization_header_carries_every_field_the_server_checks) {
  const auto challenge = parse_challenge("Digest realm=\"ketviet\",nonce=\"n1\",opaque=\"o1\",algorithm=MD5,qop=\"auth\"");
  CHECK(challenge.has_value());
  const auto value = authorization_value({"1001", "pw"}, *challenge, "INVITE", "sip:*43@127.0.0.1");
  CHECK(value.has_value());
  for (const char* field : {"username=\"1001\"", "realm=\"ketviet\"", "nonce=\"n1\"", "uri=\"sip:*43@127.0.0.1\"",
                            "qop=auth", "nc=00000001", "cnonce=\"", "opaque=\"o1\"", "algorithm=MD5"}) {
    CHECK(value->find(field) != std::string::npos);
  }
}

TEST(challenges_without_nonce_or_with_other_algorithms_are_refused) {
  CHECK(!parse_challenge("Digest realm=\"ketviet\"").has_value());
  CHECK(!parse_challenge("Basic realm=\"ketviet\"").has_value());
  const auto sha = parse_challenge("Digest realm=\"r\", nonce=\"n\", algorithm=SHA-256");
  CHECK(sha.has_value());
  CHECK(!authorization_value({"u", "p"}, *sha, "REGISTER", "sip:x").has_value());
}
