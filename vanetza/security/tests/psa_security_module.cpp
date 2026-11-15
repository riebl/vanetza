#include <vanetza/security/ecies.hpp>
#include <vanetza/security/psa_crypto_provider.hpp>
#include <vanetza/security/psa_security_module.hpp>
#include <vanetza/security/psa_wrapper.hpp>
#include <vanetza/security/public_key.hpp>
#include <vanetza/security/scoped_key_pair.hpp>
#include <vanetza/security/sha.hpp>
#include <gtest/gtest.h>
#include <psa/crypto.h>
#include <string>

using vanetza::ByteBuffer;
using vanetza::create_byte_view;
using vanetza::expected;
using namespace vanetza::security;

class PsaSecurityModuleTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        // tests use the PSA Crypto API directly as well
        ASSERT_EQ(PSA_SUCCESS, psa::initialize());
    }

    PsaSecurityModule security;
};

namespace
{

// uncompressed form of a public key, e.g. as carried by some certificates
PublicKey uncompressed(const PublicKey& key)
{
    const ByteBuffer point = psa::encode_uncompressed_point(key).value();
    PublicKey uncompressed = key;
    uncompressed.compression = KeyCompression::NoCompression;
    uncompressed.y.assign(point.begin() + 1 + key.x.size(), point.end());
    return uncompressed;
}

} // namespace

// persistent keys are found again by this derivation, i.e. it must not change between releases
TEST_F(PsaSecurityModuleTest, key_reference_is_key_id_derived_from_public_key)
{
    ScopedKeyPair key_pair { security, security.create_signing_key(KeyType::NistP256).value() };
    const PublicKey public_key = security.public_key(key_pair.reference()).value();

    // 30 bits of SHA-256 over the canonical hex string of the public key, i.e. a key identifier of the user range
    const std::string name = canonical_hexstring(public_key);
    const auto* octets = reinterpret_cast<const std::uint8_t*>(name.data());
    PsaCryptoProvider crypto;
    const Sha256Hash digest = crypto.calculate_sha256_hash(octets, name.size());
    ByteBuffer expected_reference(digest.octets.begin(), digest.octets.begin() + 4);
    expected_reference.front() &= 0x3F;
    EXPECT_EQ(expected_reference, key_pair.reference().data);
}

TEST_F(PsaSecurityModuleTest, created_key_is_found_by_its_public_key)
{
    ScopedKeyPair key_pair { security, security.create_signing_key(KeyType::BrainpoolP256r1).value() };
    const PublicKey public_key = security.public_key(key_pair.reference()).value();

    for (const PublicKey& form : { public_key, uncompressed(public_key) }) {
        SCOPED_TRACE(form.compression == KeyCompression::NoCompression ? "uncompressed key" : "compressed key");
        expected<KeyReference> found = security.find_signing_key(form);
        ASSERT_TRUE(found.has_value()) << found.error().message();
        EXPECT_EQ(key_pair.reference().data, found->data);
    }
}

TEST_F(PsaSecurityModuleTest, discarded_key_is_neither_found_nor_usable)
{
    expected<KeyReference> key = security.create_signing_key(KeyType::NistP256);
    ASSERT_TRUE(key.has_value());
    const PublicKey public_key = security.public_key(*key).value();
    ASSERT_TRUE(security.discard_key(*key));

    expected<KeyReference> found = security.find_signing_key(public_key);
    ASSERT_TRUE(found.has_error());
    EXPECT_EQ(SecurityModuleError::KeyNotFound, found.error());
    expected<Signature> signature = security.sign(ByteBuffer(32, 0x01), *key);
    ASSERT_TRUE(signature.has_error());
    EXPECT_EQ(SecurityModuleError::InvalidKeyReference, signature.error());
}

TEST_F(PsaSecurityModuleTest, malformed_key_reference_is_invalid)
{
    const struct
    {
        const char* defect;
        ByteBuffer data;
    } malformed[] = {
        { "empty", ByteBuffer {} },
        { "too short", ByteBuffer { 0x01, 0x02, 0x03 } },
        { "too long", ByteBuffer { 0x01, 0x02, 0x03, 0x04, 0x05 } },
        { "null key identifier", ByteBuffer { 0x00, 0x00, 0x00, 0x00 } },
        { "key identifier of implementation", ByteBuffer { 0x40, 0x00, 0x00, 0x00 } },
    };

    for (const auto& reference : malformed) {
        SCOPED_TRACE(reference.defect);
        expected<Signature> signature = security.sign(ByteBuffer(32, 0x01), KeyReference { reference.data });
        ASSERT_TRUE(signature.has_error());
        EXPECT_EQ(SecurityModuleError::InvalidKeyReference, signature.error());
        EXPECT_FALSE(security.discard_key(KeyReference { reference.data }));
    }
}

// PSA assigns identifiers beyond the user range to temporary keys, e.g. of other PSA users
TEST_F(PsaSecurityModuleTest, reference_to_temporary_key_is_invalid)
{
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&attributes, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&attributes, 256);
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_SIGN_HASH);
    psa_set_key_algorithm(&attributes, PSA_ALG_ECDSA_ANY);
    psa::Key temporary;
    ASSERT_EQ(PSA_SUCCESS, psa_generate_key(&attributes, temporary.output()));

    expected<Signature> signature = security.sign(ByteBuffer(32, 0x01), psa::key_reference(temporary.id()));
    ASSERT_TRUE(signature.has_error());
    EXPECT_EQ(SecurityModuleError::InvalidKeyReference, signature.error());
}

// other PSA users may store keys of any purpose with identifiers of the user range
TEST_F(PsaSecurityModuleTest, key_of_other_purpose_is_not_used)
{
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_id(&attributes, PSA_KEY_ID_USER_MAX);
    psa_set_key_type(&attributes, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&attributes, 256);
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_DERIVE);
    psa_set_key_algorithm(&attributes, PSA_ALG_ECDH);
    psa::Key foreign;
    ASSERT_EQ(PSA_SUCCESS, psa_generate_key(&attributes, foreign.output()));

    expected<Signature> signature = security.sign(ByteBuffer(32, 0x01), psa::key_reference(foreign.id()));
    ASSERT_TRUE(signature.has_error());
    EXPECT_EQ(SecurityModuleError::InvalidKeyReference, signature.error());
    expected<PublicKey> public_key = security.public_key(psa::key_reference(foreign.id()));
    ASSERT_TRUE(public_key.has_error());
    EXPECT_EQ(SecurityModuleError::InvalidKeyReference, public_key.error());
}

// other PSA users may store keys with any identifier of the user range
TEST_F(PsaSecurityModuleTest, foreign_key_is_neither_found_nor_discarded)
{
    expected<KeyReference> key = security.create_signing_key(KeyType::NistP256);
    ASSERT_TRUE(key.has_value());
    const PublicKey public_key = security.public_key(*key).value();
    ASSERT_TRUE(security.discard_key(*key));

    // foreign signing key at the identifier derived from our discarded key
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_id(&attributes, psa::key_id(*key).value());
    psa_set_key_type(&attributes, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&attributes, 256);
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_SIGN_HASH);
    psa_set_key_algorithm(&attributes, PSA_ALG_ECDSA_ANY);
    psa_key_id_t foreign = PSA_KEY_ID_NULL;
    ASSERT_EQ(PSA_SUCCESS, psa_generate_key(&attributes, &foreign));

    expected<KeyReference> found = security.find_signing_key(public_key);
    EXPECT_TRUE(found.has_error());
    EXPECT_FALSE(security.discard_key(*key));
    psa_key_attributes_t stored = PSA_KEY_ATTRIBUTES_INIT;
    EXPECT_EQ(PSA_SUCCESS, psa_get_key_attributes(foreign, &stored));
    psa_reset_key_attributes(&stored);
    EXPECT_EQ(PSA_SUCCESS, psa_destroy_key(foreign));
}

// The recipient derives the shared secret from its private key and the ephemeral public key. The module's wrapped key
// and tag match those of the IEEE-validated security::encrypt_key only if the module used the recipient's public key.
TEST_F(PsaSecurityModuleTest, key_is_encrypted_for_recipient)
{
    const Aes128Key key {{
        0x91, 0x69, 0x15, 0x5B, 0x08, 0xB0, 0x76, 0x74, 0xCB, 0xAD, 0xF7, 0x5F, 0xB4, 0x6A, 0x7B, 0x0D
    }};
    const Sha256Hash info { 0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef };

    for (KeyType type : { KeyType::NistP256, KeyType::BrainpoolP256r1 }) {
        SCOPED_TRACE(static_cast<int>(type));
        psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
        psa_set_key_type(&attributes, PSA_KEY_TYPE_ECC_KEY_PAIR(psa::ecc_family(type)));
        psa_set_key_bits(&attributes, 8 * key_length(type));
        psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_DERIVE);
        psa_set_key_algorithm(&attributes, PSA_ALG_ECDH);
        psa::Key recipient;
        ASSERT_EQ(PSA_SUCCESS, psa_generate_key(&attributes, recipient.output()));

        ByteBuffer point(1 + 2 * key_length(type));
        std::size_t point_length = 0;
        ASSERT_EQ(PSA_SUCCESS, psa_export_public_key(recipient.id(), point.data(), point.size(), &point_length));
        PublicKey recipient_key;
        recipient_key.type = type;
        recipient_key.compression = KeyCompression::NoCompression;
        recipient_key.x.assign(point.begin() + 1, point.begin() + 1 + key_length(type));
        recipient_key.y.assign(point.begin() + 1 + key_length(type), point.end());
        PublicKey compressed_recipient_key = recipient_key;
        compressed_recipient_key.compression = point.back() % 2 == 0 ? KeyCompression::Y0 : KeyCompression::Y1;
        compressed_recipient_key.y.clear();

        for (const PublicKey& form : { recipient_key, compressed_recipient_key }) {
            SCOPED_TRACE(form.compression == KeyCompression::NoCompression ? "uncompressed key" : "compressed key");
            expected<EncryptedSymmetricKey> encrypted = security.encrypt_key(form, key, info);
            ASSERT_TRUE(encrypted.has_value()) << encrypted.error().message();

            const ByteBuffer ephemeral = psa::encode_uncompressed_point(encrypted->public_key).value();
            ByteBuffer shared_secret(key_length(type));
            std::size_t secret_length = 0;
            ASSERT_EQ(PSA_SUCCESS, psa_raw_key_agreement(PSA_ALG_ECDH, recipient.id(), ephemeral.data(),
                ephemeral.size(), shared_secret.data(), shared_secret.size(), &secret_length));

            PsaCryptoProvider crypto;
            const EncryptedSymmetricKey reference = vanetza::security::encrypt_key(crypto, encrypted->public_key,
                create_byte_view(shared_secret), key, info).value();
            EXPECT_EQ(reference.wrapped_key, encrypted->wrapped_key);
            EXPECT_EQ(reference.authentication_tag, encrypted->authentication_tag);
        }
    }
}

namespace
{

// arbitrary valid scalar of NIST P-256
PrivateKey p256_private_key()
{
    PrivateKey key;
    key.type = KeyType::NistP256;
    key.key = ByteBuffer(32, 0x11);
    return key;
}

} // namespace

TEST_F(PsaSecurityModuleTest, imported_key_is_found_by_its_public_key)
{
    expected<KeyReference> imported = security.import_signing_key(p256_private_key());
    ASSERT_TRUE(imported.has_value()) << imported.error().message();
    ScopedKeyPair key_pair { security, *imported };

    const PublicKey public_key = security.public_key(key_pair.reference()).value();
    expected<KeyReference> found = security.find_signing_key(public_key);
    ASSERT_TRUE(found.has_value()) << found.error().message();
    EXPECT_EQ(key_pair.reference().data, found->data);
    EXPECT_TRUE(security.sign(ByteBuffer(32, 0x5A), key_pair.reference()).has_value());
}

// migrations may import the same key twice
TEST_F(PsaSecurityModuleTest, key_imported_again_has_same_reference)
{
    expected<KeyReference> first = security.import_signing_key(p256_private_key());
    ASSERT_TRUE(first.has_value()) << first.error().message();
    ScopedKeyPair key_pair { security, *first };

    expected<KeyReference> second = security.import_signing_key(p256_private_key());
    ASSERT_TRUE(second.has_value()) << second.error().message();
    EXPECT_EQ(first->data, second->data);
}

TEST_F(PsaSecurityModuleTest, foreign_key_prevents_import)
{
    expected<KeyReference> key = security.import_signing_key(p256_private_key());
    ASSERT_TRUE(key.has_value());
    ASSERT_TRUE(security.discard_key(*key));

    // foreign signing key at the identifier derived from the imported key
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_id(&attributes, psa::key_id(*key).value());
    psa_set_key_type(&attributes, PSA_KEY_TYPE_ECC_KEY_PAIR(PSA_ECC_FAMILY_SECP_R1));
    psa_set_key_bits(&attributes, 256);
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_SIGN_HASH);
    psa_set_key_algorithm(&attributes, PSA_ALG_ECDSA_ANY);
    psa_key_id_t foreign = PSA_KEY_ID_NULL;
    ASSERT_EQ(PSA_SUCCESS, psa_generate_key(&attributes, &foreign));

    expected<KeyReference> imported = security.import_signing_key(p256_private_key());
    EXPECT_TRUE(imported.has_error());
    psa_key_attributes_t stored = PSA_KEY_ATTRIBUTES_INIT;
    EXPECT_EQ(PSA_SUCCESS, psa_get_key_attributes(foreign, &stored));
    psa_reset_key_attributes(&stored);
    EXPECT_EQ(PSA_SUCCESS, psa_destroy_key(foreign));
}

TEST_F(PsaSecurityModuleTest, malformed_private_key_cannot_be_imported)
{
    PrivateKey key = p256_private_key();
    key.type = KeyType::Unspecified;
    EXPECT_EQ(SecurityModuleError::UnsupportedKeyType, security.import_signing_key(key).error());

    key = p256_private_key();
    key.key.pop_back();
    EXPECT_EQ(SecurityModuleError::InvalidPrivateKey, security.import_signing_key(key).error());
    key.key.assign(32, 0x00);
    EXPECT_EQ(SecurityModuleError::InvalidPrivateKey, security.import_signing_key(key).error());
    key.key.assign(32, 0xFF);
    EXPECT_EQ(SecurityModuleError::InvalidPrivateKey, security.import_signing_key(key).error());
}
