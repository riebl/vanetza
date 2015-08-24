#include <gtest/gtest.h>
#include <vanetza/security/encryption_parameter.hpp>
#include <vanetza/security/tests/set_elements.hpp>
#include <vanetza/security/tests/test_elements.hpp>

using namespace vanetza::security;

EncryptionParameter serialize(const EncryptionParameter& param)
{
    std::stringstream stream;
    OutputArchive oa(stream);
    serialize(oa, param);

    SymmetricAlgorithm sym;
    EncryptionParameter deParam;
    InputArchive ia(stream);
    deserialize(ia, deParam, sym);
    return deParam;
}

TEST(EncryptionParameter, serialize)
{
    EncryptionParameter param = setEncryptionParemeter_nonce();
    EncryptionParameter deParam = serialize(param);
    EXPECT_EQ(get_size(param), get_size(deParam));
    testEncryptionParemeter_nonce(param, deParam);
}
