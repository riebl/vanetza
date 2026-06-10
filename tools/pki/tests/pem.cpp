#include "pem.hpp"
#include <gtest/gtest.h>

using namespace vanetza::pki;

static const std::string privKeyPem =
    "-----BEGIN EC PRIVATE KEY-----\n"
    "MHcCAQEEIHlpKyVDNCQ2x5IFeBelQyyvANI8iTFIoCTfNARm1LVxoAoGCCqGSM49\n"
    "AwEHoUQDQgAEvfkk5CcwIqP29fGu9n6kXmojUpV2xUlnM2BwJMoYmiVU7lF9p7tu\n"
    "+KUbGlhPaYLN0UZ13KQTmi3gV3aLolyXUw==\n"
    "-----END EC PRIVATE KEY-----";

static const vanetza::ByteBuffer privKeyRaw = {
    0x79, 0x69, 0x2b, 0x25, 0x43, 0x34, 0x24, 0x36,
    0xc7, 0x92, 0x05, 0x78, 0x17, 0xa5, 0x43, 0x2c,
    0xaf, 0x00, 0xd2, 0x3c, 0x89, 0x31, 0x48, 0xa0,
    0x24, 0xdf, 0x34, 0x04, 0x66, 0xd4, 0xb5, 0x71
};

TEST(ReadPemPrivateKey, valid_prime256v1)
{
    boost::optional<PrivateKey> key = parse_pem_private_key(privKeyPem);
    ASSERT_TRUE(key);
    EXPECT_EQ(KeyType::NistP256, key->type);
    EXPECT_EQ(privKeyRaw, key->key);
}

TEST(ReadPemPrivateKey, invalid_pem)
{
    EXPECT_FALSE(parse_pem_private_key("not a PEM"));
    EXPECT_FALSE(parse_pem_private_key(""));
}

TEST(WritePemPrivateKey, roundtrip_generated)
{
    for (KeyType type : { KeyType::NistP256, KeyType::BrainpoolP256r1, KeyType::BrainpoolP384r1 }) {
        PrivateKey generated = generate_private_key(type);
        std::string pem = make_pem(generated);

        boost::optional<PrivateKey> parsed = parse_pem_private_key(pem);
        ASSERT_TRUE(parsed);
        EXPECT_EQ(generated.type, parsed->type);
        EXPECT_EQ(generated.key, parsed->key);
    }
}
