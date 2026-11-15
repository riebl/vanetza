#include <vanetza/security/cryptopp_crypto_provider.hpp>
#include <vanetza/security/cryptopp_security_module.hpp>
#include <vanetza/security/cryptopp_wrapper.hpp>
#include <vanetza/security/ecies.hpp>
#include <cryptopp/eccrypto.h>
#include <cryptopp/osrng.h>
#include <gtest/gtest.h>

using vanetza::ByteBuffer;
using vanetza::create_byte_view;
using vanetza::expected;
using namespace vanetza::security;

// recipients derive the module's shared secret of its ephemeral key by Crypto++'s ECDH
TEST(CryptoppSecurityModule, key_is_encrypted_for_recipient)
{
    CryptoppSecurityModule security;
    CryptoPP::AutoSeededRandomPool rng;
    const Aes128Key key {{
        0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C
    }};
    const Sha256Hash info { 0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef };

    for (KeyType type : { KeyType::NistP256, KeyType::BrainpoolP256r1, KeyType::BrainpoolP384r1 }) {
        SCOPED_TRACE(static_cast<int>(type));
        CryptoPP::ECDH<CryptoPP::ECP>::Domain recipient { cryptopp::get_oid(type) };
        recipient.AccessGroupParameters().SetPointCompression(true);
        CryptoPP::SecByteBlock recipient_private(recipient.PrivateKeyLength());
        CryptoPP::SecByteBlock recipient_public(recipient.PublicKeyLength());
        recipient.GenerateKeyPair(rng, recipient_private, recipient_public);
        const boost::optional<PublicKey> recipient_key =
            decode_ec_point(type, ByteBuffer(recipient_public.begin(), recipient_public.end()));
        ASSERT_TRUE(recipient_key);

        expected<EncryptedSymmetricKey> encrypted = security.encrypt_key(*recipient_key, key, info);
        ASSERT_TRUE(encrypted.has_value()) << encrypted.error().message();

        // agreement decodes the ephemeral key in its given form
        CryptoPP::ECDH<CryptoPP::ECP>::Domain agreement { cryptopp::get_oid(type) };
        agreement.AccessGroupParameters().SetPointCompression(
            encrypted->public_key.compression != KeyCompression::NoCompression);
        const ByteBuffer ephemeral = encode_ec_point(encrypted->public_key);
        ASSERT_EQ(agreement.PublicKeyLength(), ephemeral.size());
        ByteBuffer shared_secret(agreement.AgreedValueLength());
        ASSERT_TRUE(agreement.Agree(shared_secret.data(), recipient_private, ephemeral.data()));

        CryptoppCryptoProvider crypto;
        const EncryptedSymmetricKey reference =
            encrypt_key(crypto, encrypted->public_key, create_byte_view(shared_secret), key, info).value();
        EXPECT_EQ(reference.wrapped_key, encrypted->wrapped_key);
        EXPECT_EQ(reference.authentication_tag, encrypted->authentication_tag);
    }
}

// unlike compressed points, uncompressed points may be off the curve, e.g. for invalid curve attacks
TEST(CryptoppSecurityModule, recipient_key_off_curve_is_invalid)
{
    PublicKey off_curve;
    off_curve.type = KeyType::NistP256;
    off_curve.compression = KeyCompression::NoCompression;
    off_curve.x.assign(32, 0x11);
    off_curve.y.assign(32, 0x11);

    CryptoppSecurityModule security;
    expected<EncryptedSymmetricKey> encrypted = security.encrypt_key(off_curve, Aes128Key {}, Sha256Hash {});
    ASSERT_TRUE(encrypted.has_error());
    EXPECT_EQ(SecurityModuleError::InvalidPublicKey, encrypted.error());
}
