#include <gtest/gtest.h>
#include <vanetza/security/public_key.hpp>

using namespace vanetza;
using namespace vanetza::security;
using namespace std;

TEST(PublicKey, canonical_hexstring_y0)
{
    PublicKey key;
    key.type = KeyType::NistP256;
    key.compression = KeyCompression::Y0;
    key.x = ByteBuffer(32, 0x00);
    EXPECT_EQ("02" + std::string(64, '0'), canonical_hexstring(key));
}

TEST(PublicKey, canonical_hexstring_y1)
{
    PublicKey key;
    key.type = KeyType::BrainpoolP384r1;
    key.compression = KeyCompression::Y1;
    key.x = ByteBuffer(48, 0x00);
    EXPECT_EQ("03" + std::string(96, '0'), canonical_hexstring(key));
}

TEST(PublicKey, canonical_hexstring_encoding)
{
    PublicKey key;
    key.type = KeyType::NistP256;
    key.compression = KeyCompression::Y0;
    key.x = {
        0x00, 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd,
        0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32,
        0x10, 0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba,
        0xbe, 0x00, 0xff, 0x11, 0xee, 0x22, 0xdd, 0x33
    };
    auto expected = "02"
        "000123456789ABCD"
        "EFFEDCBA98765432"
        "10DEADBEEFCAFEBA"
        "BE00FF11EE22DD33";
    EXPECT_EQ(expected, canonical_hexstring(key));
}

TEST(PublicKey, canonical_hexstring_uncompressed_parity)
{
    PublicKey key;
    key.type = KeyType::NistP256;
    key.compression = KeyCompression::NoCompression;
    key.x = ByteBuffer(32, 0xab);
    key.y = ByteBuffer(32, 0x04);
    EXPECT_EQ("02", canonical_hexstring(key).substr(0, 2));

    key.y = ByteBuffer(32, 0x05);
    EXPECT_EQ("03", canonical_hexstring(key).substr(0, 2));
}

TEST(PublicKey, canonical_hexstring_rejects_malformed)
{
    PublicKey key;
    key.compression = KeyCompression::Y0;

    key.type = KeyType::Unspecified;
    key.x = ByteBuffer(32, 0xab);
    EXPECT_TRUE(canonical_hexstring(key).empty());

    key.type = KeyType::NistP256;
    key.x.clear();
    EXPECT_TRUE(canonical_hexstring(key).empty());

    key.x = ByteBuffer(31, 0xab);
    EXPECT_TRUE(canonical_hexstring(key).empty());

    key.x = ByteBuffer(32, 0xab);
    key.compression = KeyCompression::NoCompression;
    EXPECT_TRUE(canonical_hexstring(key).empty());

    key.y = ByteBuffer(31, 0x04);
    EXPECT_TRUE(canonical_hexstring(key).empty());
}
