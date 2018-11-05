#include <gtest/gtest.h>
#include <vanetza/common/byte_sequence.hpp>
#include <vanetza/security/public_key.hpp>
#include <vanetza/security/tests/check_public_key.hpp>

using namespace vanetza::security;
using namespace vanetza;
using namespace std;

PublicKey serialize(PublicKey key)
{
    std::stringstream stream;
    OutputArchive oa(stream);
    serialize(oa, key);

    PublicKey deKey;
    InputArchive ia(stream);
    deserialize(ia, deKey);
    return deKey;
}

TEST(PublicKey, Field_Size)
{
    EXPECT_EQ(32, field_size(PublicKeyAlgorithm::ECDSA_NISTP256_With_SHA256));
    EXPECT_EQ(32, field_size(PublicKeyAlgorithm::ECIES_NISTP256));
}

TEST(PublicKey, ECIES_NISTP256)
{
    ecies_nistp256 ecies;
    ecies.public_key = Uncompressed { random_byte_sequence(32, 1), random_byte_sequence(32, 2) };
    ecies.supported_symm_alg = SymmetricAlgorithm::AES128_CCM;
    PublicKey key = ecies;

    PublicKey deKey = serialize(key);
    check(key, deKey);
    EXPECT_EQ(PublicKeyAlgorithm::ECIES_NISTP256, get_type(deKey));
    EXPECT_EQ(67, get_size(deKey));
}

TEST(PublicKey, ECDSA_NISTP256_With_SHA256)
{
    ecdsa_nistp256_with_sha256 ecdsa;
    ecdsa.public_key = X_Coordinate_Only { random_byte_sequence(32, 1) };
    PublicKey key = ecdsa;

    PublicKey deKey = serialize(key);
    check(key, deKey);
    EXPECT_EQ(PublicKeyAlgorithm::ECDSA_NISTP256_With_SHA256, get_type(deKey));
    EXPECT_EQ(34, get_size(deKey));
}
