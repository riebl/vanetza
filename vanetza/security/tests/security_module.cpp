#include <vanetza/security/crypto_provider.hpp>
#include <vanetza/security/scoped_key_pair.hpp>
#include <vanetza/security/security_module.hpp>
#include <gtest/gtest.h>
#include <string>
#include <vector>

using vanetza::ByteBuffer;
using vanetza::create_byte_view;
using vanetza::expected;
using namespace vanetza::security;

/**
 * Test vectors from IEEE 1609.2-2017 (Annex D)
 */

// every security module implementation fulfils the same contract, tests discard their keys from the modules
class SecurityModuleTest : public ::testing::TestWithParam<std::string>
{
public:
    void SetUp() override
    {
        ASSERT_TRUE(security) << GetParam() << " security module is not built in";
    }

protected:
    std::shared_ptr<SecurityModule> security = create_security_module(GetParam());
    const ByteBuffer plaintext { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99 };
    const Sha256Hash info { 0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF };
};

TEST_P(SecurityModuleTest, signing_key_has_requested_type)
{
    expected<KeyReference> key = security->create_signing_key(KeyType::BrainpoolP256r1);
    ASSERT_TRUE(key.has_value());
    ScopedKeyPair key_pair { *security, *key };
    expected<PublicKey> public_key = security->public_key(*key);
    ASSERT_TRUE(public_key.has_value());
    EXPECT_EQ(KeyType::BrainpoolP256r1, public_key->type);
}

TEST_P(SecurityModuleTest, signature_verifies_with_public_key_of_reference)
{
    expected<KeyReference> key = security->create_signing_key(KeyType::NistP256);
    ASSERT_TRUE(key.has_value());
    ScopedKeyPair key_pair { *security, *key };
    Sha256Hash digest;
    digest.octets.fill(0x5A);
    expected<Signature> signature = security->sign(ByteBuffer(digest.octets.begin(), digest.octets.end()), *key);
    ASSERT_TRUE(signature.has_value());
    expected<PublicKey> public_key = security->public_key(*key);
    ASSERT_TRUE(public_key.has_value());

    std::unique_ptr<CryptoProvider> crypto = create_crypto_provider();
    if (!crypto) {
        GTEST_SKIP() << "no crypto provider built in";
    }
    EXPECT_TRUE(crypto->verify(digest, *signature, *public_key).value());
}

// applications store key references to use their keys again, e.g. after a restart
TEST_P(SecurityModuleTest, key_reference_is_usable_by_another_module_instance)
{
    expected<KeyReference> key = security->create_signing_key(KeyType::NistP256);
    ASSERT_TRUE(key.has_value());
    ScopedKeyPair key_pair { *security, *key };
    expected<PublicKey> public_key = security->public_key(*key);
    ASSERT_TRUE(public_key.has_value());

    std::unique_ptr<SecurityModule> other = create_security_module(GetParam());
    expected<PublicKey> other_public_key = other->public_key(*key);
    ASSERT_TRUE(other_public_key.has_value());
    EXPECT_EQ(public_key->x, other_public_key->x);
    EXPECT_EQ(public_key->compression, other_public_key->compression);
    EXPECT_TRUE(other->sign(ByteBuffer(32, 0x5A), *key).has_value());
}

TEST_P(SecurityModuleTest, unsupported_key_type_cannot_be_created)
{
    expected<KeyReference> key = security->create_signing_key(KeyType::Unspecified);
    ASSERT_TRUE(key.has_error());
    EXPECT_EQ(SecurityModuleError::UnsupportedKeyType, key.error());
}

TEST_P(SecurityModuleTest, generated_aes_keys_differ)
{
    expected<Aes128Key> first = security->generate_aes_key();
    expected<Aes128Key> second = security->generate_aes_key();
    ASSERT_TRUE(first.has_value());
    ASSERT_TRUE(second.has_value());
    EXPECT_NE(*first, *second);
}

TEST_P(SecurityModuleTest, generated_hmac_keys_differ)
{
    expected<HmacKey> first = security->generate_hmac_key();
    expected<HmacKey> second = security->generate_hmac_key();
    ASSERT_TRUE(first.has_value());
    ASSERT_TRUE(second.has_value());
    EXPECT_NE(*first, *second);
}

TEST_P(SecurityModuleTest, key_encryption_requires_valid_recipient_key)
{
    expected<Aes128Key> key = security->generate_aes_key();
    ASSERT_TRUE(key.has_value());

    ScopedKeyPair recipient_key_pair { *security, security->create_signing_key(KeyType::NistP256).value() };
    PublicKey recipient = security->public_key(recipient_key_pair.reference()).value();
    recipient.type = KeyType::Unspecified;
    expected<EncryptedSymmetricKey> encrypted = security->encrypt_key(recipient, *key, info);
    ASSERT_TRUE(encrypted.has_error());
    EXPECT_EQ(SecurityModuleError::UnsupportedKeyType, encrypted.error());

    recipient.type = KeyType::NistP256;
    recipient.x.assign(32, 0xFF); // not on curve
    encrypted = security->encrypt_key(recipient, *key, info);
    ASSERT_TRUE(encrypted.has_error());
    EXPECT_EQ(SecurityModuleError::InvalidPublicKey, encrypted.error());
}

std::vector<std::string> enabled_security_modules()
{
    std::vector<std::string> modules;
#ifdef VANETZA_WITH_OPENSSL
    modules.emplace_back("OpenSSL");
#endif
#ifdef VANETZA_WITH_PSA
    modules.emplace_back("PSA");
#endif
    return modules;
}

INSTANTIATE_TEST_SUITE_P(Implementations, SecurityModuleTest, ::testing::ValuesIn(enabled_security_modules()),
    [](const ::testing::TestParamInfo<std::string>& info) { return info.param; });

// builds without any security module have nothing to test
GTEST_ALLOW_UNINSTANTIATED_PARAMETERIZED_TEST(SecurityModuleTest);
