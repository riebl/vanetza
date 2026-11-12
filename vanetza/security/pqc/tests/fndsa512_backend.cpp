#include <vanetza/security/pqc/fndsa512.hpp>
#include <vanetza/security/security_module_error.hpp>
#include <gtest/gtest.h>

using vanetza::ByteBuffer;
using vanetza::expected;
using namespace vanetza::security;

TEST(FnDsa512Backend, signature_by_created_key_verifies)
{
    auto backend = pqc::create_fndsa512_backend();
    expected<pqc::SigningKey> key = backend->create_signing_key();
    ASSERT_TRUE(key.has_value());

    const ByteBuffer data { 1, 2, 3, 4 };
    expected<pqc::Signature> signature = backend->sign(key->reference, data);
    ASSERT_TRUE(signature.has_value());
    EXPECT_TRUE(backend->verify(key->public_key, data, *signature));
}

TEST(FnDsa512Backend, reference_of_wrong_size_is_invalid)
{
    auto backend = pqc::create_fndsa512_backend();
    expected<pqc::SigningKey> key = backend->create_signing_key();
    ASSERT_TRUE(key.has_value());
    const ByteBuffer data { 1, 2, 3, 4 };

    KeyReference truncated = key->reference;
    truncated.data.pop_back();
    expected<pqc::Signature> truncated_signature = backend->sign(truncated, data);
    ASSERT_FALSE(truncated_signature.has_value());
    EXPECT_EQ(SecurityModuleError::InvalidKeyReference, truncated_signature.error());

    KeyReference extended = key->reference;
    extended.data.push_back(0);
    expected<pqc::Signature> extended_signature = backend->sign(extended, data);
    ASSERT_FALSE(extended_signature.has_value());
    EXPECT_EQ(SecurityModuleError::InvalidKeyReference, extended_signature.error());
}
