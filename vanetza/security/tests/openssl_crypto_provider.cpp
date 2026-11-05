#include <vanetza/security/openssl_crypto_provider.hpp>
#include <vanetza/security/openssl_security_module.hpp>
#include <gtest/gtest.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <memory>

using vanetza::ByteBuffer;
using vanetza::expected;
using namespace vanetza::security;

class OpenSslCryptoProviderTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        // some tests check that the provider leaves no errors in OpenSSL's error queue
        ERR_clear_error();
    }

    OpenSslCryptoProvider crypto;
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

TEST_F(OpenSslCryptoProviderTest, is_builtin_default)
{
    std::unique_ptr<CryptoProvider> provider = create_crypto_provider("OpenSSL");
    EXPECT_NE(nullptr, dynamic_cast<OpenSslCryptoProvider*>(provider.get()));
    EXPECT_NE(nullptr, create_crypto_provider());
}

TEST_F(OpenSslCryptoProviderTest, tampered_ciphertext_is_reported_with_openssl_error)
{
    const Aes128Key key {};
    expected<AesCcmCiphertext> ciphertext = crypto.encrypt_aes_ccm(key, ByteBuffer(10, 0x5A));
    ASSERT_TRUE(ciphertext.has_value());
    ciphertext->ciphertext.back() ^= 0x01; // authentication tag
    expected<ByteBuffer> decrypted = crypto.decrypt_aes_ccm(key, *ciphertext);
    ASSERT_TRUE(decrypted.has_error());
    EXPECT_EQ(SecurityModuleError::DecryptionFailure, decrypted.error());
    EXPECT_STREQ("openssl.decryption_failure", decrypted.error().category().name());
    EXPECT_EQ(0u, ERR_peek_error());
}

TEST_F(OpenSslCryptoProviderTest, unusable_public_key_is_reported_by_verification)
{
    Signature signature;
    signature.type = KeyType::NistP256;
    signature.r.assign(32, 0x01);
    signature.s.assign(32, 0x01);

    PublicKey malformed;
    malformed.type = KeyType::NistP256;
    malformed.compression = KeyCompression::Y0;
    malformed.x.assign(33, 0x11); // exceeds field length
    PublicKey unspecified = off_curve_public_key();
    unspecified.type = KeyType::Unspecified;

    const struct
    {
        const char* defect;
        PublicKey key;
        SecurityModuleError error;
    } unusable_keys[] = {
        { "not on curve", off_curve_public_key(), SecurityModuleError::InvalidPublicKey },
        { "malformed", malformed, SecurityModuleError::InvalidPublicKey },
        { "unspecified key type", unspecified, SecurityModuleError::UnsupportedKeyType },
    };

    for (const auto& unusable : unusable_keys) {
        SCOPED_TRACE(unusable.defect);
        expected<bool> verified = crypto.verify(Sha256Hash {}, signature, unusable.key);
        ASSERT_TRUE(verified.has_error());
        EXPECT_EQ(unusable.error, verified.error());
        EXPECT_EQ(0u, ERR_peek_error());
    }
}

TEST_F(OpenSslCryptoProviderTest, unverifiable_signature_is_false_leaving_openssl_error_queue_unchanged)
{
    OpenSslSecurityModule module;
    expected<KeyReference> reference = module.create_signing_key(KeyType::NistP256);
    ASSERT_TRUE(reference.has_value());
    expected<PublicKey> public_key = module.public_key(*reference);
    ASSERT_TRUE(public_key.has_value());
    expected<Signature> signature = module.sign(ByteBuffer(32, 0x01), *reference);
    ASSERT_TRUE(signature.has_value());

    Signature out_of_range = *signature;
    out_of_range.r = ByteBuffer { 0x00 }; // valid r and s are greater than zero
    out_of_range.s = ByteBuffer { 0x00 };
    Signature empty = *signature;
    empty.r.clear();
    Signature other_curve = *signature;
    other_curve.type = KeyType::BrainpoolP256r1;

    const struct
    {
        const char* defect;
        Signature signature;
    } unverifiable[] = {
        { "signature of other digest", *signature },
        { "r and s out of range", out_of_range },
        { "empty r", empty },
        { "signature for other curve", other_curve },
    };

    for (const auto& candidate : unverifiable) {
        SCOPED_TRACE(candidate.defect);
        // error queued by someone else before verification
        ERR_raise(ERR_LIB_EC, EC_R_POINT_IS_NOT_ON_CURVE);
        const unsigned long queued = ERR_peek_last_error();

        Sha256Hash digest;
        digest.octets.fill(0x02);
        expected<bool> verified = crypto.verify(digest, candidate.signature, *public_key);
        ASSERT_TRUE(verified.has_value());
        EXPECT_FALSE(*verified);
        EXPECT_EQ(queued, ERR_get_error());
        EXPECT_EQ(0u, ERR_peek_error());
    }
}
