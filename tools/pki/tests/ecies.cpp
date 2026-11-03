#include "keys.hpp"
#include "mock_credential_storage.hpp"
#include "openssl_security_module.hpp"
#include <gtest/gtest.h>

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
