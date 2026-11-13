#include <vanetza/security/pem.hpp>
#include <gtest/gtest.h>
#include <string>

using vanetza::ByteBuffer;
using namespace vanetza::security;

namespace
{

ByteBuffer bytes(const std::string& text)
{
    return ByteBuffer(text.begin(), text.end());
}

// octets 0x00 to 0x30, its base64 encoding exceeds a line of 64 characters
ByteBuffer sequence()
{
    ByteBuffer data;
    for (std::uint8_t octet = 0; octet < 49; ++octet) {
        data.push_back(octet);
    }
    return data;
}

} // namespace

TEST(PemEncoding, encode_wraps_base64_lines_after_64_characters)
{
    EXPECT_EQ("-----BEGIN TEST-----\n"
              "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8gISIjJCUmJygpKissLS4v\n"
              "MA==\n"
              "-----END TEST-----\n",
        encode_pem("TEST", sequence()));
}

TEST(PemEncoding, encode_pads_base64)
{
    EXPECT_EQ("-----BEGIN TEST-----\nZg==\n-----END TEST-----\n", encode_pem("TEST", bytes("f")));
    EXPECT_EQ("-----BEGIN TEST-----\nZm8=\n-----END TEST-----\n", encode_pem("TEST", bytes("fo")));
    EXPECT_EQ("-----BEGIN TEST-----\nZm9v\n-----END TEST-----\n", encode_pem("TEST", bytes("foo")));
}

TEST(PemEncoding, decode_reverses_encode)
{
    ByteBuffer data;
    for (std::uint8_t octet = 0; octet < 70; ++octet) {
        const boost::optional<ByteBuffer> decoded = decode_pem("PUBLIC KEY", encode_pem("PUBLIC KEY", data));
        ASSERT_TRUE(decoded) << data.size() << " octets";
        EXPECT_EQ(data, *decoded);
        data.push_back(octet ^ 0xa5);
    }
}

TEST(PemEncoding, decode_ignores_text_around_block_and_line_endings)
{
    const std::string pem = "explanatory text\r\n"
                            "-----BEGIN TEST-----\r\n"
                            "Zm9v\r\n"
                            "-----END TEST-----\r\n"
                            "trailing text";
    const boost::optional<ByteBuffer> decoded = decode_pem("TEST", pem);
    ASSERT_TRUE(decoded);
    EXPECT_EQ(bytes("foo"), *decoded);
}

TEST(PemEncoding, decode_rejects_other_label)
{
    EXPECT_FALSE(decode_pem("PUBLIC KEY", encode_pem("PRIVATE KEY", bytes("foo"))));
}

TEST(PemEncoding, decode_rejects_missing_end_line)
{
    EXPECT_FALSE(decode_pem("TEST", "-----BEGIN TEST-----\nZm9v\n"));
}

TEST(PemEncoding, decode_rejects_malformed_base64)
{
    EXPECT_FALSE(decode_pem("TEST", "-----BEGIN TEST-----\nZm9!\n-----END TEST-----\n"));
    // incomplete quantum
    EXPECT_FALSE(decode_pem("TEST", "-----BEGIN TEST-----\nZm9\n-----END TEST-----\n"));
    // padding within a quantum
    EXPECT_FALSE(decode_pem("TEST", "-----BEGIN TEST-----\nZg=v\n-----END TEST-----\n"));
    // padding of more than two symbols
    EXPECT_FALSE(decode_pem("TEST", "-----BEGIN TEST-----\nZ===\n-----END TEST-----\n"));
    // padding before the last quantum
    EXPECT_FALSE(decode_pem("TEST", "-----BEGIN TEST-----\nZg==Zm9v\n-----END TEST-----\n"));
}
