#include <gtest/gtest.h>
#include <vanetza/common/byte_sequence.hpp>
#include <vanetza/security/public_key.hpp>
#include <vanetza/security/v2/public_key.hpp>
#include <vanetza/security/tests/check_public_key.hpp>

using namespace vanetza;
using namespace vanetza::security;
using namespace std;

v2::PublicKey serialize(v2::PublicKey key)
{
    std::stringstream stream;
    OutputArchive oa(stream);
    serialize(oa, key);

    v2::PublicKey deKey;
    InputArchive ia(stream);
    deserialize(ia, deKey);
    return deKey;
}

TEST(PublicKey, Field_Size)
{
    EXPECT_EQ(32, field_size(v2::PublicKeyAlgorithm::ECDSA_NISTP256_With_SHA256));
    EXPECT_EQ(32, field_size(v2::PublicKeyAlgorithm::ECIES_NISTP256));
}

TEST(PublicKey, ECIES_NISTP256)
{
    v2::ecies_nistp256 ecies;
    ecies.public_key = Uncompressed { random_byte_sequence(32, 1), random_byte_sequence(32, 2) };
    ecies.supported_symm_alg = v2::SymmetricAlgorithm::AES128_CCM;
    v2::PublicKey key = ecies;

    v2::PublicKey deKey = serialize(key);
    check(key, deKey);
    EXPECT_EQ(v2::PublicKeyAlgorithm::ECIES_NISTP256, get_type(deKey));
    EXPECT_EQ(67, get_size(deKey));
}

TEST(PublicKey, ECDSA_NISTP256_With_SHA256)
{
    v2::ecdsa_nistp256_with_sha256 ecdsa;
    ecdsa.public_key = X_Coordinate_Only { random_byte_sequence(32, 1) };
    v2::PublicKey key = ecdsa;

    v2::PublicKey deKey = serialize(key);
    check(key, deKey);
    EXPECT_EQ(v2::PublicKeyAlgorithm::ECDSA_NISTP256_With_SHA256, get_type(deKey));
    EXPECT_EQ(34, get_size(deKey));
}

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
