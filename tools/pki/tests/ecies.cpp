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
