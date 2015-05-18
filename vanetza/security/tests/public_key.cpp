#include <gtest/gtest.h>
#include <vanetza/security/public_key.hpp>
#include <vanetza/security/ecc_point.hpp>
#include <vanetza/security/tests/set_elements.hpp>
#include <vanetza/security/tests/test_elements.hpp>

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

TEST(publicKey_serialize, Ecies_Nistp256)
{
    PublicKey key = setPublicKey_Ecies_Nistp256();
    PublicKey deKey = serialize(key);
    testPublicKey_Ecies_Nistp256(key, deKey);
}

TEST(publicKey_serialize, Ecdsa_Nistp256_With_Sha256)
{
    PublicKey key = setPublicKey_Ecdsa_Nistp256_With_Sha256();
    PublicKey deKey = serialize(key);
    testPublicKey_Ecdsa_Nistp256_With_Sha256(key, deKey);
}
