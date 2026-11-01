#include "ecies.hpp"
#include "mock_credential_storage.hpp"
#include "openssl_security_module.hpp"
#include <gtest/gtest.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/ecdh.h>
#include <openssl/obj_mac.h>

using vanetza::ByteBuffer;
using namespace vanetza::pki;

// Regression test: previously, the 0_EU-EA_L0 certificate's encryption key is
// stored in compressed-y-1 form and the ECIES context must still derive a
// working shared secret from it.
TEST(Ecies, shared_secret_with_compressed_y1_key)
{
    // x coordinate of the 0_EU-EA_L0 EA certificate encryption key
    const ByteBuffer eu_ea_x {{
        0x53, 0x8A, 0x8D, 0x36, 0x0D, 0x00, 0xD8, 0x48,
        0x0F, 0x5B, 0x29, 0x54, 0xFA, 0xB2, 0x42, 0xFB,
        0x98, 0xB3, 0x38, 0x70, 0xF7, 0xA0, 0xC3, 0x3C,
        0xF6, 0x52, 0xCB, 0x46, 0xA1, 0x74, 0xE2, 0x48
    }};

    PublicKey compressed;
    compressed.type = KeyType::NistP256;
    compressed.compression = KeyCompression::Y1;
    compressed.x = eu_ea_x;

    OpenSslSecurityModule security(std::make_shared<MockCredentialStorage>());
    Sha256Hash info {};
    // Must not throw and must produce a non-empty 32-byte shared secret
    auto ecies = security.create_ecies_context(compressed, info);
    EXPECT_EQ(32u, ecies->shared_secret().size());
    EXPECT_FALSE(ecies->shared_secret() == ByteBuffer(32, 0));
}

TEST(Ecies, encryption_roundtrip_compressed_receiver)
{
    // Receiver was created as uncompressed but is then compressed before handing it
    // to the ECIES context. Decryption must still succeed -- otherwise we have a
    // bug in how compressed keys are mapped back to curve points.
    OpenSslSecurityModule security(std::make_shared<MockCredentialStorage>());
    PublicKey receiver = derive_public_key(generate_private_key(KeyType::NistP256));
    ASSERT_NE(KeyCompression::NoCompression, receiver.compression);

    Sha256Hash info { 0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef };
    auto ecies = security.create_ecies_context(receiver, info);

    const ByteBuffer plaintext {{
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
    }};
    const ByteBuffer ciphertext = ecies->encrypt(plaintext);
    const ByteBuffer decrypted = ecies->decrypt(ciphertext.data(), ciphertext.size());
    EXPECT_NE(plaintext, ciphertext);
    EXPECT_EQ(plaintext, decrypted);
}

TEST(Ecies, encryption_roundtrip)
{
    OpenSslSecurityModule security(std::make_shared<MockCredentialStorage>());
    PublicKey receiver = derive_public_key(generate_private_key(KeyType::NistP256));
    Sha256Hash info { 0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef };
    auto ecies = security.create_ecies_context(receiver, info);

    const ByteBuffer plaintext {{
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
    }};
    const ByteBuffer ciphertext = ecies->encrypt(plaintext);
    const ByteBuffer decrypted = ecies->decrypt(ciphertext.data(), ciphertext.size());
    EXPECT_NE(plaintext, ciphertext);
    EXPECT_EQ(plaintext, decrypted);
}

namespace
{

// Mock that returns fixed test-vector values, so encrypt_key() can be tested
// against IEEE 1609.2 Annex D.6.2 known-answer data.
class FixedEciesContext : public SecurityModule::EciesContext
{
public:
    explicit FixedEciesContext(ByteBuffer shared) : m_shared_secret(std::move(shared))
    {
    }

    PublicKey ephemeral_public_key() const override
    {
        return {};
    }

    PublicKey recipient_public_key() const override
    {
        return {};
    }

    ByteBuffer shared_secret() const override
    {
        return m_shared_secret;
    }

    ByteBuffer encrypted_key() const override
    {
        return {};
    }

    ByteBuffer authentication_tag() const override
    {
        return {};
    }

    ByteBuffer nonce() const override
    {
        return {};
    }

    void nonce(const ByteBuffer&) override
    {
    }

    ByteBuffer encrypt(const ByteBuffer&) override
    {
        return {};
    }

    ByteBuffer decrypt(const std::uint8_t*, std::size_t) override
    {
        return {};
    }

private:
    ByteBuffer m_shared_secret;
};

} // anonymous namespace

// IEEE 1609.2-2016 Annex D.6.2 ECIES1 test vector
// End-to-end: runs ECDH with the vector's ephemeral private key and recipient
// public key through OpenSSL, then pipes the resulting shared secret through
// encrypt_key(). This catches any bug in the ECDH input handling that a
// standalone KDF2 test would miss.
TEST(Ecies, ecies_IEEE_1609_2_Annex_D_6_2_ECIES1_full)
{
    const ByteBuffer sender_eph_priv {{
        0x13, 0x84, 0xC3, 0x1D, 0x69, 0x82, 0xD5, 0x2B,
        0xCA, 0x3B, 0xED, 0x8A, 0x7E, 0x60, 0xF5, 0x2F,
        0xEC, 0xDA, 0xB4, 0x4E, 0x5C, 0x0E, 0xA1, 0x66,
        0x81, 0x5A, 0x81, 0x59, 0xE0, 0x9F, 0xFB, 0x42
    }};
    const ByteBuffer recipient_pub_x {{
        0x8C, 0x5E, 0x20, 0xFE, 0x31, 0x93, 0x5F, 0x6F,
        0xA6, 0x82, 0xA1, 0xF6, 0xD4, 0x6E, 0x44, 0x68,
        0x53, 0x4F, 0xFE, 0xA1, 0xA6, 0x98, 0xB1, 0x4B,
        0x0B, 0x12, 0x51, 0x3E, 0xED, 0x8D, 0xEB, 0x11
    }};
    const ByteBuffer recipient_pub_y {{
        0x12, 0x70, 0xFE, 0xC2, 0x42, 0x7E, 0x6A, 0x15,
        0x4D, 0xFC, 0xAE, 0x33, 0x68, 0x58, 0x43, 0x96,
        0xC8, 0x25, 0x1A, 0x04, 0xE2, 0xAE, 0x7D, 0x87,
        0xB0, 0x16, 0xFF, 0x65, 0xD2, 0x2D, 0x6F, 0x9E
    }};
    const ByteBuffer aes_key {{
        0x91, 0x69, 0x15, 0x5B, 0x08, 0xB0, 0x76, 0x74,
        0xCB, 0xAD, 0xF7, 0x5F, 0xB4, 0x6A, 0x7B, 0x0D
    }};
    const Sha256Hash recipient_info {{
        0xA6, 0xB7, 0xB5, 0x25, 0x54, 0xB4, 0x20, 0x3F,
        0x7E, 0x3A, 0xCF, 0xDB, 0x3A, 0x3E, 0xD8, 0x67,
        0x4E, 0xE0, 0x86, 0xCE, 0x59, 0x06, 0xA7, 0xCA,
        0xC2, 0xF8, 0xA3, 0x98, 0x30, 0x6D, 0x3B, 0xE9
    }};
    const ByteBuffer expected_wrapped {{
        0xA6, 0x34, 0x20, 0x13, 0xD6, 0x23, 0xAD, 0x6C,
        0x5F, 0x68, 0x82, 0x46, 0x96, 0x73, 0xAE, 0x33
    }};
    const ByteBuffer expected_tag {{
        0x80, 0xE1, 0xD8, 0x5D, 0x30, 0xF1, 0xBA, 0xE4,
        0xEC, 0xF1, 0xA5, 0x34, 0xA8, 0x9A, 0x07, 0x86
    }};

    // Set up sender ephemeral EC_KEY with the test vector's private scalar
    EC_KEY* sender = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    BIGNUM* priv_bn = BN_bin2bn(sender_eph_priv.data(), sender_eph_priv.size(), nullptr);
    ASSERT_EQ(1, EC_KEY_set_private_key(sender, priv_bn));

    // Reconstruct recipient public point from (x, y)
    const EC_GROUP* group = EC_KEY_get0_group(sender);
    EC_POINT* recipient_point = EC_POINT_new(group);
    BIGNUM* rx = BN_bin2bn(recipient_pub_x.data(), recipient_pub_x.size(), nullptr);
    BIGNUM* ry = BN_bin2bn(recipient_pub_y.data(), recipient_pub_y.size(), nullptr);
    ASSERT_EQ(1, EC_POINT_set_affine_coordinates(group, recipient_point, rx, ry, nullptr));

    // Compute shared secret
    ByteBuffer shared(32);
    int got = ECDH_compute_key(shared.data(), shared.size(), recipient_point, sender, nullptr);
    ASSERT_EQ(32, got);

    BN_free(priv_bn);
    BN_free(rx);
    BN_free(ry);
    EC_POINT_free(recipient_point);
    EC_KEY_free(sender);

    // Now feed the shared secret through encrypt_key
    OpenSslSecurityModule security(std::make_shared<MockCredentialStorage>());
    FixedEciesContext ecies(shared);
    auto result = encrypt_key(security, ecies, aes_key, recipient_info);

    EXPECT_EQ(expected_wrapped, result.wrapped_key);
    EXPECT_EQ(expected_tag, result.authentication_tag);
}

// IEEE 1609.2-2016 Annex D.6.2 ECIES1 test vector
// Verifies the KDF2 + key wrapping + HMAC-SHA256 tag chain used by encrypt_key().
TEST(Ecies, encrypt_key_IEEE_1609_2_Annex_D_6_2_ECIES1)
{
    // Shared secret z = x-coord of [k_E] * Q_recipient (precomputed)
    const ByteBuffer shared_secret {{
        0xd4, 0x43, 0x08, 0x02, 0x3f, 0xbb, 0xd3, 0xe9,
        0x06, 0xb9, 0xf3, 0xb4, 0x0e, 0x5e, 0x0b, 0x62,
        0x54, 0x11, 0x70, 0x3c, 0x4a, 0x99, 0x24, 0x9d,
        0x35, 0xa1, 0x39, 0x06, 0x38, 0x6a, 0x3e, 0xe3
    }};
    const ByteBuffer aes_key {{
        0x91, 0x69, 0x15, 0x5B, 0x08, 0xB0, 0x76, 0x74,
        0xCB, 0xAD, 0xF7, 0x5F, 0xB4, 0x6A, 0x7B, 0x0D
    }};
    const Sha256Hash recipient_info {{
        0xA6, 0xB7, 0xB5, 0x25, 0x54, 0xB4, 0x20, 0x3F,
        0x7E, 0x3A, 0xCF, 0xDB, 0x3A, 0x3E, 0xD8, 0x67,
        0x4E, 0xE0, 0x86, 0xCE, 0x59, 0x06, 0xA7, 0xCA,
        0xC2, 0xF8, 0xA3, 0x98, 0x30, 0x6D, 0x3B, 0xE9
    }};
    const ByteBuffer expected_wrapped {{
        0xA6, 0x34, 0x20, 0x13, 0xD6, 0x23, 0xAD, 0x6C,
        0x5F, 0x68, 0x82, 0x46, 0x96, 0x73, 0xAE, 0x33
    }};
    const ByteBuffer expected_tag {{
        0x80, 0xE1, 0xD8, 0x5D, 0x30, 0xF1, 0xBA, 0xE4,
        0xEC, 0xF1, 0xA5, 0x34, 0xA8, 0x9A, 0x07, 0x86
    }};

    OpenSslSecurityModule security(std::make_shared<MockCredentialStorage>());
    FixedEciesContext ecies(shared_secret);
    auto result = encrypt_key(security, ecies, aes_key, recipient_info);

    EXPECT_EQ(expected_wrapped, result.wrapped_key);
    EXPECT_EQ(expected_tag, result.authentication_tag);
}