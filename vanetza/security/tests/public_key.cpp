#include <gtest/gtest.h>
#include <vanetza/security/public_key.hpp>
#include "serialization.hpp"

using namespace vanetza;
using namespace vanetza::security;
using namespace std;

namespace
{

// NIST P-256 generator, FIPS 186-4 D.1.2.3
PublicKey nist_p256_generator()
{
    PublicKey key;
    key.type = KeyType::NistP256;
    key.compression = KeyCompression::NoCompression;
    key.x = buffer_from_hexstring("6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296");
    key.y = buffer_from_hexstring("4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5");
    return key;
}

// brainpoolP256r1 generator in compressed form, RFC 5639 section 3.4
PublicKey brainpool_p256r1_generator()
{
    PublicKey key;
    key.type = KeyType::BrainpoolP256r1;
    key.compression = KeyCompression::Y1;
    key.x = buffer_from_hexstring("8BD2AEB9CB7E57CB2C4B482FFC81B7AFB9DE27E1E3BD23C23A4453BD9ACE3262");
    return key;
}

} // namespace

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

TEST(PublicKey, encode_ec_point_uncompressed)
{
    const ByteBuffer expected =
        buffer_from_hexstring("04"
                              "6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296"
                              "4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5");
    EXPECT_EQ(expected, encode_ec_point(nist_p256_generator()));
}

TEST(PublicKey, encode_ec_point_compressed)
{
    PublicKey key = nist_p256_generator();
    key.y.clear();

    key.compression = KeyCompression::Y0;
    EXPECT_EQ(buffer_from_hexstring("02"
                                    "6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296"),
        encode_ec_point(key));

    key.compression = KeyCompression::Y1;
    EXPECT_EQ(buffer_from_hexstring("03"
                                    "6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296"),
        encode_ec_point(key));
}

TEST(PublicKey, encode_ec_point_pads_short_coordinates)
{
    // big-endian integers lacking leading zero octets, e.g. from OpenSSL's BN_bn2bin
    PublicKey key;
    key.type = KeyType::NistP256;
    key.compression = KeyCompression::NoCompression;
    key.x = ByteBuffer(31, 0xab);
    key.y = ByteBuffer(30, 0xcd);

    ByteBuffer expected { 0x04, 0x00 };
    expected.insert(expected.end(), 31, 0xab);
    expected.insert(expected.end(), 2, 0x00);
    expected.insert(expected.end(), 30, 0xcd);
    EXPECT_EQ(expected, encode_ec_point(key));
}

TEST(PublicKey, encode_ec_point_strips_leading_zeros)
{
    // big-endian integer with a leading zero octet, e.g. a DER INTEGER of a value with most significant bit set
    PublicKey key;
    key.type = KeyType::BrainpoolP384r1;
    key.compression = KeyCompression::Y0;
    key.x = ByteBuffer(48, 0xab);
    key.x.insert(key.x.begin(), 0x00);

    ByteBuffer expected { 0x02 };
    expected.insert(expected.end(), 48, 0xab);
    EXPECT_EQ(expected, encode_ec_point(key));
}

TEST(PublicKey, encode_ec_point_rejects_malformed)
{
    PublicKey key;
    key.compression = KeyCompression::Y0;

    key.type = KeyType::Unspecified;
    key.x = ByteBuffer(32, 0xab);
    EXPECT_TRUE(encode_ec_point(key).empty());

    key.type = KeyType::NistP256;
    key.x.clear();
    EXPECT_TRUE(encode_ec_point(key).empty());

    // value exceeds the curve's field length
    key.x = ByteBuffer(33, 0xab);
    EXPECT_TRUE(encode_ec_point(key).empty());

    key.x = ByteBuffer(32, 0xab);
    key.compression = KeyCompression::NoCompression;
    EXPECT_TRUE(encode_ec_point(key).empty());

    key.y = ByteBuffer(33, 0xcd);
    EXPECT_TRUE(encode_ec_point(key).empty());
}

// expected DER generated by OpenSSL 3.5 "asn1parse -genconf" and accepted as EC public key by "pkey -pubin"
TEST(PublicKey, encode_subject_public_key_info_uncompressed)
{
    const ByteBuffer expected =
        buffer_from_hexstring("3059301306072A8648CE3D020106082A8648CE3D03010703420004"
                              "6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296"
                              "4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5");
    EXPECT_EQ(expected, encode_subject_public_key_info(nist_p256_generator()));
}

// expected DER generated by OpenSSL 3.5 "asn1parse -genconf" and accepted as EC public key by "pkey -pubin"
TEST(PublicKey, encode_subject_public_key_info_compressed)
{
    const ByteBuffer expected =
        buffer_from_hexstring("303A301406072A8648CE3D020106092B240303020801010703220003"
                              "8BD2AEB9CB7E57CB2C4B482FFC81B7AFB9DE27E1E3BD23C23A4453BD9ACE3262");
    EXPECT_EQ(expected, encode_subject_public_key_info(brainpool_p256r1_generator()));
}
