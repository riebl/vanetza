#include "hexstring.hpp"
#include <gtest/gtest.h>

using namespace vanetza;
using namespace vanetza::pki;

TEST(HexString, encode_buffer)
{
    const ByteBuffer buffer { 0x00, 0x0f, 0xa5, 0xff };
    EXPECT_EQ("000FA5FF", hexstring(buffer));
    EXPECT_EQ("", hexstring(ByteBuffer {}));
}

TEST(HexString, encode_pointer)
{
    const std::uint8_t bytes[] { 0xde, 0xad, 0xbe, 0xef };
    EXPECT_EQ("DEADBEEF", hexstring(bytes, sizeof(bytes)));
}

TEST(HexString, encode_array)
{
    const std::array<std::uint8_t, 3> array { 0x01, 0x23, 0x45 };
    EXPECT_EQ("012345", hexstring(array));
}

TEST(HexString, encode_string)
{
    EXPECT_EQ("414243", hexstring(std::string { "ABC" }));
}

TEST(HexString, is_valid_accepts_hex)
{
    EXPECT_TRUE(is_valid_hexstring("00"));
    EXPECT_TRUE(is_valid_hexstring("DEADBEEF"));
    EXPECT_TRUE(is_valid_hexstring("deadbeef"));
    EXPECT_TRUE(is_valid_hexstring("0123456789abcdefABCDEF"));
}

TEST(HexString, is_valid_rejects_empty)
{
    EXPECT_FALSE(is_valid_hexstring(""));
}

TEST(HexString, is_valid_rejects_odd_length)
{
    EXPECT_FALSE(is_valid_hexstring("0"));
    EXPECT_FALSE(is_valid_hexstring("abc"));
}

TEST(HexString, is_valid_rejects_non_hex)
{
    EXPECT_FALSE(is_valid_hexstring("0g"));
    EXPECT_FALSE(is_valid_hexstring("xy"));
    EXPECT_FALSE(is_valid_hexstring("12 34"));
    EXPECT_FALSE(is_valid_hexstring("0x12"));
}

TEST(HexString, parse_decodes_to_bytes)
{
    const std::string raw = parse_hexstring("DEADBEEF");
    const ByteBuffer expected { 0xde, 0xad, 0xbe, 0xef };
    EXPECT_EQ(ByteBuffer(raw.begin(), raw.end()), expected);
}

TEST(HexString, parse_is_case_insensitive)
{
    EXPECT_EQ(parse_hexstring("abcdef"), parse_hexstring("ABCDEF"));
}

TEST(HexString, parse_roundtrip)
{
    const ByteBuffer buffer { 0x00, 0x7f, 0x80, 0xff };
    const std::string raw = parse_hexstring(hexstring(buffer));
    EXPECT_EQ(ByteBuffer(raw.begin(), raw.end()), buffer);
}
