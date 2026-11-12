#include "openssl_security_module.hpp"
#include <vanetza/security/memory_credential_storage.hpp>
#include <gtest/gtest.h>
#include <memory>

using vanetza::expected;
using vanetza::security::MemoryCredentialStorage;
using vanetza::security::SecurityModuleError;
using namespace vanetza::pki;

class ScopedKeyPairTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        key = security.create_signing_key(KeyType::NistP256).value();
        public_key = security.public_key(key).value();
    }

    OpenSslSecurityModule security { std::make_shared<MemoryCredentialStorage>() };
    KeyReference key;
    PublicKey public_key;
};

TEST_F(ScopedKeyPairTest, key_is_discarded_at_end_of_scope)
{
    auto scoped = std::make_unique<ScopedKeyPair>(security, key);
    scoped.reset();
    expected<KeyReference> found = security.find_signing_key(public_key);
    ASSERT_TRUE(found.has_error());
    EXPECT_EQ(SecurityModuleError::KeyNotFound, found.error());
}

TEST_F(ScopedKeyPairTest, committed_key_is_kept)
{
    auto scoped = std::make_unique<ScopedKeyPair>(security, key);
    EXPECT_EQ(key.data, scoped->reference().data);
    scoped->commit();
    scoped.reset();
    EXPECT_TRUE(security.find_signing_key(public_key).has_value());
}
