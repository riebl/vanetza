#include "keys.hpp"
#include "mock_credential_storage.hpp"
#include "openssl.hpp"
#include "openssl_security_module.hpp"
#include <vanetza/security/ecies.hpp>
#include <vanetza/security/tests/printer.hpp>
#include <gtest/gtest.h>
#include <openssl/ec.h>

using vanetza::ByteBuffer;
using vanetza::create_byte_view;
using vanetza::expected;
using vanetza::security::Aes128Key;
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

TEST(Ecies, key_encryption_with_compressed_y1_key)
{
    // a curve point's x-coordinate also belongs to a curve point with odd y, i.e. it is a valid compressed-y-1 key
    PublicKey compressed = derive_public_key(generate_private_key(KeyType::NistP256));
    compressed.compression = KeyCompression::Y1;

    OpenSslSecurityModule security(std::make_shared<MockCredentialStorage>());
    Sha256Hash info {};
    Aes128Key key {};
    EXPECT_TRUE(security.encrypt_key(compressed, key, info).has_value());
}

namespace
{

// public key in uncompressed form as carried by some certificates
PublicKey decompress(const PublicKey& compressed)
{
    OpenSslPointer<EC_GROUP> group { EC_GROUP_new_by_curve_name(openssl_nid(compressed.type)) };
    OpenSslPointer<BIGNUM> x { BN_new() };
    OpenSslPointer<BIGNUM> y { BN_new() };
    openssl_result(
        EC_POINT_get_affine_coordinates(group.raw(), make_ec_point(compressed).raw(), x.raw(), y.raw(), nullptr),
        "get affine");
    PublicKey uncompressed = compressed;
    uncompressed.compression = KeyCompression::NoCompression;
    uncompressed.y = make_buffer(y.raw(), compressed.x.size());
    return uncompressed;
}

// The recipient derives the shared secret from its private key and the ephemeral public key. The module's wrapped key
// and tag match those of the IEEE-validated security::encrypt_key only if the module used the recipient's public key.
void expect_key_encrypted_for(const PrivateKey& recipient, const PublicKey& recipient_key)
{
    const Aes128Key key {{
        0x91, 0x69, 0x15, 0x5B, 0x08, 0xB0, 0x76, 0x74,
        0xCB, 0xAD, 0xF7, 0x5F, 0xB4, 0x6A, 0x7B, 0x0D
    }};
    const Sha256Hash info { 0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef };
    OpenSslSecurityModule security(std::make_shared<MockCredentialStorage>());
    expected<EncryptedSymmetricKey> encrypted = security.encrypt_key(recipient_key, key, info);
    ASSERT_TRUE(encrypted.has_value());

    const PublicKey& ephemeral = encrypted->public_key;
    ByteBuffer shared_secret(vanetza::security::key_length(recipient.type));
    ASSERT_EQ(static_cast<int>(shared_secret.size()),
        ECDH_compute_key(shared_secret.data(), shared_secret.size(), make_ec_point(ephemeral).raw(),
            make_ec_key(recipient).raw(), nullptr));

    const EncryptedSymmetricKey reference =
        vanetza::security::encrypt_key(ephemeral, create_byte_view(shared_secret), key, info);
    EXPECT_EQ(reference.wrapped_key, encrypted->wrapped_key);
    EXPECT_EQ(reference.authentication_tag, encrypted->authentication_tag);
}

} // namespace

TEST(Ecies, key_encryption_for_compressed_recipient_key)
{
    for (KeyType type : { KeyType::NistP256, KeyType::BrainpoolP256r1 }) {
        SCOPED_TRACE(type);
        const PrivateKey recipient = generate_private_key(type);
        expect_key_encrypted_for(recipient, derive_public_key(recipient));
    }
}

TEST(Ecies, key_encryption_for_uncompressed_recipient_key)
{
    for (KeyType type : { KeyType::NistP256, KeyType::BrainpoolP256r1 }) {
        SCOPED_TRACE(type);
        const PrivateKey recipient = generate_private_key(type);
        expect_key_encrypted_for(recipient, decompress(derive_public_key(recipient)));
    }
}
