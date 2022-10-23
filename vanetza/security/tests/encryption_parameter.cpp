#include <gtest/gtest.h>
#include <vanetza/common/byte_sequence.hpp>
#include <vanetza/security/v2/encryption_parameter.hpp>
#include <vanetza/security/tests/check_encryption_parameter.hpp>
#include <vanetza/security/tests/serialization.hpp>
#include <algorithm>

using namespace vanetza::security::v2;

TEST(EncryptionParameter, Nonce)
{
    Nonce nonce;
    auto random = vanetza::random_byte_sequence(nonce.size());
    std::copy_n(random.begin(), nonce.size(), nonce.begin());
    EncryptionParameter param = nonce;
    check(param, serialize_roundtrip(param));
}
