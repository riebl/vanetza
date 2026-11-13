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

TEST(PublicKey, decode_ec_point_uncompressed)
{
    const ByteBuffer encoded =
        buffer_from_hexstring("04"
                              "6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296"
                              "4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5");
    const boost::optional<PublicKey> key = decode_ec_point(KeyType::NistP256, encoded);
    ASSERT_TRUE(key);
    EXPECT_EQ(KeyType::NistP256, key->type);
    EXPECT_EQ(KeyCompression::NoCompression, key->compression);
    EXPECT_EQ(nist_p256_generator().x, key->x);
    EXPECT_EQ(nist_p256_generator().y, key->y);
}

TEST(PublicKey, decode_ec_point_compressed)
{
    const ByteBuffer x = nist_p256_generator().x;

    ByteBuffer encoded { 0x02 };
    encoded.insert(encoded.end(), x.begin(), x.end());
    boost::optional<PublicKey> key = decode_ec_point(KeyType::NistP256, encoded);
    ASSERT_TRUE(key);
    EXPECT_EQ(KeyCompression::Y0, key->compression);
    EXPECT_EQ(x, key->x);
    EXPECT_TRUE(key->y.empty());

    encoded.front() = 0x03;
    key = decode_ec_point(KeyType::NistP256, encoded);
    ASSERT_TRUE(key);
    EXPECT_EQ(KeyCompression::Y1, key->compression);
    EXPECT_EQ(x, key->x);
}

TEST(PublicKey, decode_ec_point_rejects_malformed)
{
    const ByteBuffer compressed = encode_ec_point(brainpool_p256r1_generator());
    ASSERT_FALSE(compressed.empty());
    const ByteBuffer uncompressed = encode_ec_point(nist_p256_generator());
    ASSERT_FALSE(uncompressed.empty());

    EXPECT_FALSE(decode_ec_point(KeyType::NistP256, ByteBuffer {}));
    // a curve without field length would accept a lone prefix
    EXPECT_FALSE(decode_ec_point(KeyType::Unspecified, ByteBuffer { 0x02 }));
    // encoded length does not match the curve's field length
    EXPECT_FALSE(decode_ec_point(KeyType::BrainpoolP384r1, compressed));
    EXPECT_FALSE(decode_ec_point(KeyType::BrainpoolP384r1, uncompressed));
    ByteBuffer trailing = uncompressed;
    trailing.push_back(0x00);
    EXPECT_FALSE(decode_ec_point(KeyType::NistP256, trailing));

    // point at infinity and hybrid form are not supported
    EXPECT_FALSE(decode_ec_point(KeyType::NistP256, ByteBuffer { 0x00 }));
    ByteBuffer hybrid = uncompressed;
    hybrid.front() = 0x06;
    EXPECT_FALSE(decode_ec_point(KeyType::NistP256, hybrid));

    // prefix contradicts the encoded length
    ByteBuffer short_uncompressed = compressed;
    short_uncompressed.front() = 0x04;
    EXPECT_FALSE(decode_ec_point(KeyType::BrainpoolP256r1, short_uncompressed));
    ByteBuffer long_compressed = uncompressed;
    long_compressed.front() = 0x02;
    EXPECT_FALSE(decode_ec_point(KeyType::NistP256, long_compressed));
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

TEST(PublicKey, decode_subject_public_key_info_uncompressed)
{
    const ByteBuffer encoded =
        buffer_from_hexstring("3059301306072A8648CE3D020106082A8648CE3D03010703420004"
                              "6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296"
                              "4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5");
    const boost::optional<PublicKey> key = decode_subject_public_key_info(encoded);
    ASSERT_TRUE(key);
    EXPECT_EQ(KeyType::NistP256, key->type);
    EXPECT_EQ(KeyCompression::NoCompression, key->compression);
    EXPECT_EQ(nist_p256_generator().x, key->x);
    EXPECT_EQ(nist_p256_generator().y, key->y);
}

TEST(PublicKey, decode_subject_public_key_info_compressed)
{
    const ByteBuffer encoded =
        buffer_from_hexstring("303A301406072A8648CE3D020106092B240303020801010703220003"
                              "8BD2AEB9CB7E57CB2C4B482FFC81B7AFB9DE27E1E3BD23C23A4453BD9ACE3262");
    const boost::optional<PublicKey> key = decode_subject_public_key_info(encoded);
    ASSERT_TRUE(key);
    EXPECT_EQ(KeyType::BrainpoolP256r1, key->type);
    EXPECT_EQ(KeyCompression::Y1, key->compression);
    EXPECT_EQ(brainpool_p256r1_generator().x, key->x);
}

// assembled according to RFC 5480 with the brainpoolP384r1 OID 1.3.36.3.3.2.8.1.1.11 of RFC 5639
TEST(PublicKey, decode_subject_public_key_info_brainpool_p384r1)
{
    ByteBuffer encoded = buffer_from_hexstring("307A301406072A8648CE3D020106092B240303020801010B03620004");
    encoded.insert(encoded.end(), 48, 0xab);
    encoded.insert(encoded.end(), 48, 0xcd);

    const boost::optional<PublicKey> key = decode_subject_public_key_info(encoded);
    ASSERT_TRUE(key);
    EXPECT_EQ(KeyType::BrainpoolP384r1, key->type);
    EXPECT_EQ(KeyCompression::NoCompression, key->compression);
    EXPECT_EQ(ByteBuffer(48, 0xab), key->x);
    EXPECT_EQ(ByteBuffer(48, 0xcd), key->y);
}

TEST(PublicKey, decode_subject_public_key_info_rejects_malformed)
{
    const ByteBuffer valid = encode_subject_public_key_info(brainpool_p256r1_generator());
    ASSERT_FALSE(valid.empty());
    EXPECT_FALSE(decode_subject_public_key_info(ByteBuffer {}));

    // secp384r1 (1.3.132.0.34) replaces the brainpoolP256r1 OID at octets 13 to 23, lengths are adjusted
    const ByteBuffer secp384r1 = buffer_from_hexstring("06052B81040022");
    ByteBuffer unsupported_curve = valid;
    unsupported_curve.erase(unsupported_curve.begin() + 13, unsupported_curve.begin() + 24);
    unsupported_curve.insert(unsupported_curve.begin() + 13, secp384r1.begin(), secp384r1.end());
    unsupported_curve[1] -= 4;
    unsupported_curve[3] -= 4;
    EXPECT_FALSE(decode_subject_public_key_info(unsupported_curve));

    // AlgorithmIdentifier holds an additional octet after the curve OID ending at octet 23
    ByteBuffer extended_algorithm = valid;
    extended_algorithm.insert(extended_algorithm.begin() + 24, 0x00);
    extended_algorithm[1] += 1;
    extended_algorithm[3] += 1;
    EXPECT_FALSE(decode_subject_public_key_info(extended_algorithm));

    // algorithm differs from id-ecPublicKey in its last OID arc
    ByteBuffer other_algorithm = valid;
    other_algorithm[12] ^= 0x01;
    EXPECT_FALSE(decode_subject_public_key_info(other_algorithm));

    ByteBuffer unused_bits = valid;
    unused_bits[26] = 0x01;
    EXPECT_FALSE(decode_subject_public_key_info(unused_bits));

    ByteBuffer trailing = valid;
    trailing.push_back(0x00);
    EXPECT_FALSE(decode_subject_public_key_info(trailing));

    // octet after the BIT STRING within the outer SEQUENCE
    ByteBuffer trailing_in_sequence = valid;
    trailing_in_sequence.push_back(0x00);
    trailing_in_sequence[1] += 1;
    EXPECT_FALSE(decode_subject_public_key_info(trailing_in_sequence));

    // BIT STRING without content follows the AlgorithmIdentifier ending at octet 23
    ByteBuffer empty_bit_string(valid.begin(), valid.begin() + 24);
    empty_bit_string.push_back(0x03);
    empty_bit_string.push_back(0x00);
    empty_bit_string[1] = empty_bit_string.size() - 2;
    EXPECT_FALSE(decode_subject_public_key_info(empty_bit_string));

    ByteBuffer truncated = valid;
    truncated.pop_back();
    EXPECT_FALSE(decode_subject_public_key_info(truncated));

    ByteBuffer outer_length = valid;
    outer_length[1] -= 1;
    EXPECT_FALSE(decode_subject_public_key_info(outer_length));

    // AlgorithmIdentifier length exceeds the encoding
    ByteBuffer algorithm_overrun = valid;
    algorithm_overrun[3] = 0x7f;
    EXPECT_FALSE(decode_subject_public_key_info(algorithm_overrun));

    // BIT STRING length is short of its point
    ByteBuffer short_bit_string = valid;
    short_bit_string[25] -= 1;
    EXPECT_FALSE(decode_subject_public_key_info(short_bit_string));

    // point is shorter than the curve's field length, lengths of its DER structures are consistent
    ByteBuffer short_point = valid;
    short_point.pop_back();
    short_point[1] -= 1;
    short_point[25] -= 1;
    EXPECT_FALSE(decode_subject_public_key_info(short_point));
}
