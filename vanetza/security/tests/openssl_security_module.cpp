#include <vanetza/security/memory_credential_storage.hpp>
#include <vanetza/security/openssl_security_module.hpp>
#include <gtest/gtest.h>
#include <openssl/ec.h>
#include <openssl/err.h>

using vanetza::ByteBuffer;
using vanetza::expected;
using namespace vanetza::security;

class OpenSslSecurityModuleTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        // some tests check that the module leaves no errors in OpenSSL's error queue
        ERR_clear_error();
    }

    std::shared_ptr<MemoryCredentialStorage> credentials = std::make_shared<MemoryCredentialStorage>();
    OpenSslSecurityModule security { credentials };
};

namespace
{

PublicKey off_curve_public_key()
{
    PublicKey key;
    key.type = KeyType::NistP256;
    key.compression = KeyCompression::NoCompression;
    key.x.assign(32, 0x11);
    key.y.assign(32, 0x11);
    return key;
}

} // namespace

TEST_F(OpenSslSecurityModuleTest, is_builtin_default)
{
    std::unique_ptr<SecurityModule> module = create_security_module("OpenSSL");
    EXPECT_NE(nullptr, dynamic_cast<OpenSslSecurityModule*>(module.get()));
    EXPECT_NE(nullptr, create_security_module());
}

TEST_F(OpenSslSecurityModuleTest, invalid_recipient_key_is_reported_with_openssl_error)
{
    expected<EncryptedSymmetricKey> encrypted =
        security.encrypt_key(off_curve_public_key(), Aes128Key {}, Sha256Hash {});
    ASSERT_TRUE(encrypted.has_error());
    EXPECT_EQ(SecurityModuleError::InvalidPublicKey, encrypted.error());
    EXPECT_STREQ("openssl.invalid_public_key", encrypted.error().category().name());
    EXPECT_EQ(0u, ERR_peek_error());
}
