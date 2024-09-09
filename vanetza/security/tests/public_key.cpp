#include <gtest/gtest.h>
#include <vanetza/common/byte_sequence.hpp>
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
