#include <vanetza/security/crypto_provider.hpp>
#include <vanetza/security/tests/implementations.hpp>
#include <gtest/gtest.h>
#include <algorithm>
#include <memory>
#include <string>
#include <vector>
#include "serialization.hpp"

using vanetza::ByteBuffer;
using vanetza::create_byte_view;
using vanetza::expected;
using namespace vanetza::security;

// every crypto provider implementation fulfils the same contract
class CryptoProviderTest : public ::testing::TestWithParam<std::string>
{
protected:
    void SetUp() override
    {
        ASSERT_TRUE(crypto) << GetParam() << " crypto provider is not built in";
    }

    // verify by the overload of the digest's length
    expected<bool> verify(const ByteBuffer& digest, const Signature& signature, const PublicKey& key)
    {
        Sha256Hash sha256;
        Sha384Hash sha384;
        if (digest.size() == sha256.octets.size()) {
            std::copy(digest.begin(), digest.end(), sha256.octets.begin());
            return crypto->verify(sha256, signature, key);
        } else if (digest.size() == sha384.octets.size()) {
            std::copy(digest.begin(), digest.end(), sha384.octets.begin());
            return crypto->verify(sha384, signature, key);
        } else {
            ADD_FAILURE() << "digest of unexpected length " << digest.size();
            return false;
        }
    }

    std::unique_ptr<CryptoProvider> crypto = create_crypto_provider(GetParam());
    const ByteBuffer plaintext { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99 };
    // AES-128 example key of FIPS 197 (Appendix A.1)
    const Aes128Key key {{
        0x2B, 0x7E, 0x15, 0x16, 0x28, 0xAE, 0xD2, 0xA6, 0xAB, 0xF7, 0x15, 0x88, 0x09, 0xCF, 0x4F, 0x3C
    }};
};

namespace
{

// ECDSA signature by OpenSSL of the SHA-256 or SHA-384 digest of "Vanetza ECDSA test vector"
struct SignedDigest
{
    const char* curve;
    KeyType type;
    ByteBuffer digest;
    ByteBuffer x;
    ByteBuffer y;
    ByteBuffer r;
    ByteBuffer s;
};

const std::vector<SignedDigest>& signed_digests()
{
    static const std::vector<SignedDigest> digests = {
        { "NIST P-256", KeyType::NistP256,
            buffer_from_hexstring("ef393f3f3de3c074da89cc848c3ec7c8b59e0a294086b113ed71f0c1439209a6"),
            buffer_from_hexstring("82750a96826bd2bb3bba44e5fa888d6367692b0937bc01b15cbd8ccb4ea915f0"),
            buffer_from_hexstring("4c5363e024173cc26b2e2a224257dd5753f117f9a3cbf36e69c2a01d0dec6780"),
            buffer_from_hexstring("361b4f8bd72f241f2c0fd9724b0724a89ea22f4087f4dad735dccfc172493abb"),
            buffer_from_hexstring("72a18baecf7b13c54d3dc1d4339e67704c3f5a9a34ff8f5517b21d5b997a224a") },
        { "NIST P-256 with 31-byte r", KeyType::NistP256,
            buffer_from_hexstring("ef393f3f3de3c074da89cc848c3ec7c8b59e0a294086b113ed71f0c1439209a6"),
            buffer_from_hexstring("82750a96826bd2bb3bba44e5fa888d6367692b0937bc01b15cbd8ccb4ea915f0"),
            buffer_from_hexstring("4c5363e024173cc26b2e2a224257dd5753f117f9a3cbf36e69c2a01d0dec6780"),
            buffer_from_hexstring("2d0e426e74810a5d446170762d5f0d019b4822523729b54fdfd4fc726acd29"),
            buffer_from_hexstring("f24ad500c32dcb0ee3c8a86646317793538d5d5a63c8eb688d5c5c8ecc85c6ff") },
        { "brainpoolP256r1", KeyType::BrainpoolP256r1,
            buffer_from_hexstring("ef393f3f3de3c074da89cc848c3ec7c8b59e0a294086b113ed71f0c1439209a6"),
            buffer_from_hexstring("92a34fbd72b4e475fe441bc222fbd59b499eef97cc0c4fa3329adb9c049f829d"),
            buffer_from_hexstring("61720184498f9f271c42a6e990f6e8abf58a7135a619094cf130507fe43161a5"),
            buffer_from_hexstring("2fea764cd9cbae8bafe329e07ab5a4cb9218fe4a486ea402f009d348e0bbeb28"),
            buffer_from_hexstring("7c906cbdcf9eb390ecd777cb0f2bffedc7298bf60d669b76e0865982d4c14bed") },
        { "brainpoolP384r1", KeyType::BrainpoolP384r1,
            buffer_from_hexstring(
                "62951471c7c674cc198f7ae25d19538de636d7a9b860dd5dc9e1fac61e793465b5a40e60ca8c8b90dcdf5d60b94590ab"),
            buffer_from_hexstring(
                "57b66098aaf8ca7228df09efc7652766b2bad38c60967021da3d57f310e39cf055a2b0a356c1a5b0e1e12799bb3ada48"),
            buffer_from_hexstring(
                "5174240955deda9183e6f09ca1d4c55eb83dee94739094b595f4912382feacf171fc863ee343e85f83832ce11f694ef1"),
            buffer_from_hexstring(
                "37f86aa9e05a3229025916d84afc774cb3cc43e3fa329e974e040ce6517e1f4c04bf4b368f11ffee2cd2ffe4cb493579"),
            buffer_from_hexstring(
                "32f38cf178ec27e067959bad1849faa53ca94207e4b699f35d1c526f11d5143c309302ae3155303b1969034d2eca5b3a") },
        // ECDSA uses the leftmost bits of a digest longer than the curve order
        { "NIST P-256 with SHA-384 digest", KeyType::NistP256,
            buffer_from_hexstring(
                "62951471c7c674cc198f7ae25d19538de636d7a9b860dd5dc9e1fac61e793465b5a40e60ca8c8b90dcdf5d60b94590ab"),
            buffer_from_hexstring("854607496b0574f25294399c42c85fb7cb498417f06ca739c8f9d4a51a88249a"),
            buffer_from_hexstring("4367c1a82801c6eb454eaef985d8b1aeb482667ed43e7034d4efd31987be16df"),
            buffer_from_hexstring("52c252c0fda1298c1d3d3555d4af62266c0efbd51df2d8f570c64fb307308d04"),
            buffer_from_hexstring("2651a9286459484b5101678f5d2f66c0d8d524099db5d36113312509aba305f7") },
    };
    return digests;
}

PublicKey public_key(const SignedDigest& signed_digest, KeyCompression compression)
{
    PublicKey key;
    key.type = signed_digest.type;
    key.compression = compression;
    key.x = signed_digest.x;
    if (compression == KeyCompression::NoCompression) {
        key.y = signed_digest.y;
    }
    return key;
}

KeyCompression compressed_form(const SignedDigest& signed_digest)
{
    return signed_digest.y.back() % 2 == 0 ? KeyCompression::Y0 : KeyCompression::Y1;
}

Signature signature(const SignedDigest& signed_digest)
{
    Signature signature;
    signature.type = signed_digest.type;
    signature.r = signed_digest.r;
    signature.s = signed_digest.s;
    return signature;
}

} // namespace

TEST_P(CryptoProviderTest, signature_is_verified)
{
    for (const SignedDigest& signed_digest : signed_digests()) {
        SCOPED_TRACE(signed_digest.curve);
        for (KeyCompression compression : { KeyCompression::NoCompression, compressed_form(signed_digest) }) {
            SCOPED_TRACE(compression == KeyCompression::NoCompression ? "uncompressed key" : "compressed key");
            const PublicKey key = public_key(signed_digest, compression);
            expected<bool> verified = verify(signed_digest.digest, signature(signed_digest), key);
            ASSERT_TRUE(verified.has_value()) << verified.error().message();
            EXPECT_TRUE(*verified);
        }
    }
}

TEST_P(CryptoProviderTest, signature_of_other_digest_is_false)
{
    for (const SignedDigest& signed_digest : signed_digests()) {
        SCOPED_TRACE(signed_digest.curve);
        ByteBuffer other_digest = signed_digest.digest;
        other_digest.front() ^= 0x01;
        const PublicKey key = public_key(signed_digest, KeyCompression::NoCompression);
        expected<bool> verified = verify(other_digest, signature(signed_digest), key);
        ASSERT_TRUE(verified.has_value()) << verified.error().message();
        EXPECT_FALSE(*verified);
    }
}

TEST_P(CryptoProviderTest, unverifiable_signature_is_false)
{
    const SignedDigest& signed_digest = signed_digests().front();
    Signature out_of_range = signature(signed_digest);
    out_of_range.r = ByteBuffer { 0x00 }; // valid r and s are greater than zero
    out_of_range.s = ByteBuffer { 0x00 };
    Signature empty = signature(signed_digest);
    empty.r.clear();
    Signature other_curve = signature(signed_digest);
    other_curve.type = KeyType::BrainpoolP256r1;

    const struct
    {
        const char* defect;
        Signature signature;
    } unverifiable[] = {
        { "r and s out of range", out_of_range },
        { "empty r", empty },
        { "signature for other curve", other_curve },
    };

    const PublicKey key = public_key(signed_digest, KeyCompression::NoCompression);
    for (const auto& candidate : unverifiable) {
        SCOPED_TRACE(candidate.defect);
        expected<bool> verified = verify(signed_digest.digest, candidate.signature, key);
        ASSERT_TRUE(verified.has_value()) << verified.error().message();
        EXPECT_FALSE(*verified);
    }
}

TEST_P(CryptoProviderTest, unusable_public_key_is_error)
{
    const SignedDigest& signed_digest = signed_digests().front();
    PublicKey off_curve = public_key(signed_digest, KeyCompression::NoCompression);
    off_curve.y.back() ^= 0x01;
    PublicKey malformed = public_key(signed_digest, compressed_form(signed_digest));
    malformed.x.insert(malformed.x.begin(), 0x01); // exceeds field length
    PublicKey unspecified = public_key(signed_digest, KeyCompression::NoCompression);
    unspecified.type = KeyType::Unspecified;

    const struct
    {
        const char* defect;
        PublicKey key;
        SecurityModuleError error;
    } unusable_keys[] = {
        { "not on curve", off_curve, SecurityModuleError::InvalidPublicKey },
        { "malformed", malformed, SecurityModuleError::InvalidPublicKey },
        { "unspecified key type", unspecified, SecurityModuleError::UnsupportedKeyType },
    };

    for (const auto& unusable : unusable_keys) {
        SCOPED_TRACE(unusable.defect);
        expected<bool> verified = verify(signed_digest.digest, signature(signed_digest), unusable.key);
        ASSERT_TRUE(verified.has_error());
        EXPECT_EQ(unusable.error, verified.error());
    }
}

TEST_P(CryptoProviderTest, calculate_hash_by_algorithm)
{
    const ByteBuffer data { 'a', 'b', 'c' };
    // FIPS 180-2 Appendix B.1 and D.1
    const ByteBuffer sha256 {
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
        0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad };
    const ByteBuffer sha384 {
        0xcb, 0x00, 0x75, 0x3f, 0x45, 0xa3, 0x5e, 0x8b, 0xb5, 0xa0, 0x3d, 0x69, 0x9a, 0xc6, 0x50, 0x07,
        0x27, 0x2c, 0x32, 0xab, 0x0e, 0xde, 0xd1, 0x63, 0x1a, 0x8b, 0x60, 0x5a, 0x43, 0xff, 0x5b, 0xed,
        0x80, 0x86, 0x07, 0x2b, 0xa1, 0xe7, 0xcc, 0x23, 0x58, 0xba, 0xec, 0xa1, 0x34, 0xc8, 0x25, 0xa7 };
    EXPECT_EQ(sha256, calculate_hash(*crypto, HashAlgorithm::SHA256, data));
    EXPECT_EQ(sha384, calculate_hash(*crypto, HashAlgorithm::SHA384, data));
}

TEST_P(CryptoProviderTest, calculate_hash_of_unsupported_algorithm_is_empty)
{
    EXPECT_TRUE(calculate_hash(*crypto, HashAlgorithm::Unspecified, ByteBuffer { 'a', 'b', 'c' }).empty());
}

TEST_P(CryptoProviderTest, verify_hash_by_algorithm)
{
    for (const SignedDigest& signed_digest : signed_digests()) {
        SCOPED_TRACE(signed_digest.curve);
        const HashAlgorithm algorithm =
            signed_digest.digest.size() == Sha256Hash::length ? HashAlgorithm::SHA256 : HashAlgorithm::SHA384;
        const PublicKey key = public_key(signed_digest, KeyCompression::NoCompression);
        expected<bool> verified = verify_hash(*crypto, algorithm, signed_digest.digest, signature(signed_digest), key);
        ASSERT_TRUE(verified.has_value()) << verified.error().message();
        EXPECT_TRUE(*verified);
    }
}

TEST_P(CryptoProviderTest, verify_hash_of_other_algorithm_is_error)
{
    for (const SignedDigest& signed_digest : signed_digests()) {
        SCOPED_TRACE(signed_digest.curve);
        // the given hash is shorter or longer than one of the other algorithm
        const HashAlgorithm other =
            signed_digest.digest.size() == Sha256Hash::length ? HashAlgorithm::SHA384 : HashAlgorithm::SHA256;
        const PublicKey key = public_key(signed_digest, KeyCompression::NoCompression);

        expected<bool> mismatch = verify_hash(*crypto, other, signed_digest.digest, signature(signed_digest), key);
        ASSERT_TRUE(mismatch.has_error());
        EXPECT_EQ(SecurityModuleError::InvalidHashLength, mismatch.error());

        expected<bool> unsupported = verify_hash(*crypto, HashAlgorithm::Unspecified, signed_digest.digest,
            signature(signed_digest), key);
        ASSERT_TRUE(unsupported.has_error());
        EXPECT_EQ(SecurityModuleError::UnsupportedHashAlgorithm, unsupported.error());
    }
}

TEST_P(CryptoProviderTest, mac_vector1)
{
    const ByteBuffer key(20, 0x0B);
    const ByteBuffer msg { 0x48, 0x69, 0x20, 0x54, 0x68, 0x65, 0x72, 0x65 };
    const ByteBuffer tag {
        0xB0, 0x34, 0x4C, 0x61, 0xD8, 0xDB, 0x38, 0x53,
        0x5C, 0xA8, 0xAF, 0xCE, 0xAF, 0x0B, 0xF1, 0x2B
    };
    const KeyTag result(crypto->calculate_hmac_sha256(create_byte_view(key), create_byte_view(msg)).value());
    EXPECT_EQ(create_byte_view(tag), create_byte_view(result.octets));
}

TEST_P(CryptoProviderTest, mac_vector2)
{
    const ByteBuffer key { 0x4A, 0x65, 0x66, 0x65 };
    const ByteBuffer msg {
        0x77, 0x68, 0x61, 0x74, 0x20, 0x64, 0x6F, 0x20,
        0x79, 0x61, 0x20, 0x77, 0x61, 0x6E, 0x74, 0x20,
        0x66, 0x6F, 0x72, 0x20, 0x6E, 0x6F, 0x74, 0x68,
        0x69, 0x6E, 0x67, 0x3F };
    const ByteBuffer tag {
        0x5B, 0xDC, 0xC1, 0x46, 0xBF, 0x60, 0x75, 0x4E,
        0x6A, 0x04, 0x24, 0x26, 0x08, 0x95, 0x75, 0xC7
    };
    const KeyTag result(crypto->calculate_hmac_sha256(create_byte_view(key), create_byte_view(msg)).value());
    EXPECT_EQ(create_byte_view(tag), create_byte_view(result.octets));
}

TEST_P(CryptoProviderTest, mac_vector3)
{
    const ByteBuffer key(20, 0xAA);
    const ByteBuffer msg(50, 0xDD);
    const ByteBuffer tag {
        0x77, 0x3E, 0xA9, 0x1E, 0x36, 0x80, 0x0E, 0x46,
        0x85, 0x4D, 0xB8, 0xEB, 0xD0, 0x91, 0x81, 0xA7
    };
    const KeyTag result(crypto->calculate_hmac_sha256(create_byte_view(key), create_byte_view(msg)).value());
    EXPECT_EQ(create_byte_view(tag), create_byte_view(result.octets));
}

TEST_P(CryptoProviderTest, mac_vector4)
{
    const ByteBuffer key {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19 };
    const ByteBuffer msg(50, 0xCD);
    const ByteBuffer tag {
        0x82, 0x55, 0x8A, 0x38, 0x9A, 0x44, 0x3C, 0x0E,
        0xA4, 0xCC, 0x81, 0x98, 0x99, 0xF2, 0x08, 0x3A
    };
    const KeyTag result(crypto->calculate_hmac_sha256(create_byte_view(key), create_byte_view(msg)).value());
    EXPECT_EQ(create_byte_view(tag), create_byte_view(result.octets));
}

TEST_P(CryptoProviderTest, mac_vector5)
{
    const ByteBuffer key(20, 0x0C);
    const ByteBuffer msg {
        0x54, 0x65, 0x73, 0x74, 0x20, 0x57, 0x69, 0x74,
        0x68, 0x20, 0x54, 0x72, 0x75, 0x6E, 0x63, 0x61,
        0x74, 0x69, 0x6F, 0x6E };
    const ByteBuffer tag {
        0xA3, 0xB6, 0x16, 0x74, 0x73, 0x10, 0x0E, 0xE0,
        0x6E, 0x0C, 0x79, 0x6C, 0x29, 0x55, 0x55, 0x2B
    };
    const KeyTag result(crypto->calculate_hmac_sha256(create_byte_view(key), create_byte_view(msg)).value());
    EXPECT_EQ(create_byte_view(tag), create_byte_view(result.octets));
}

TEST_P(CryptoProviderTest, mac_vector6)
{
    const ByteBuffer key(131, 0xAA);
    const ByteBuffer msg {
        0x54, 0x65, 0x73, 0x74, 0x20, 0x55, 0x73, 0x69,
        0x6E, 0x67, 0x20, 0x4C, 0x61, 0x72, 0x67, 0x65,
        0x72, 0x20, 0x54, 0x68, 0x61, 0x6E, 0x20, 0x42,
        0x6C, 0x6F, 0x63, 0x6B, 0x2D, 0x53, 0x69, 0x7A,
        0x65, 0x20, 0x4B, 0x65, 0x79, 0x20, 0x2D, 0x20,
        0x48, 0x61, 0x73, 0x68, 0x20, 0x4B, 0x65, 0x79,
        0x20, 0x46, 0x69, 0x72, 0x73, 0x74 };
    const ByteBuffer tag {
        0x60, 0xE4, 0x31, 0x59, 0x1E, 0xE0, 0xB6, 0x7F,
        0x0D, 0x8A, 0x26, 0xAA, 0xCB, 0xF5, 0xB7, 0x7F
    };
    const KeyTag result(crypto->calculate_hmac_sha256(create_byte_view(key), create_byte_view(msg)).value());
    EXPECT_EQ(create_byte_view(tag), create_byte_view(result.octets));
}

TEST_P(CryptoProviderTest, mac_vector7)
{
    const ByteBuffer key(131, 0xAA);
    const ByteBuffer msg {
        0x54, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20,
        0x61, 0x20, 0x74, 0x65, 0x73, 0x74, 0x20, 0x75,
        0x73, 0x69, 0x6E, 0x67, 0x20, 0x61, 0x20, 0x6C,
        0x61, 0x72, 0x67, 0x65, 0x72, 0x20, 0x74, 0x68,
        0x61, 0x6E, 0x20, 0x62, 0x6C, 0x6F, 0x63, 0x6B,
        0x2D, 0x73, 0x69, 0x7A, 0x65, 0x20, 0x6B, 0x65,
        0x79, 0x20, 0x61, 0x6E, 0x64, 0x20, 0x61, 0x20,
        0x6C, 0x61, 0x72, 0x67, 0x65, 0x72, 0x20, 0x74,
        0x68, 0x61, 0x6E, 0x20, 0x62, 0x6C, 0x6F, 0x63,
        0x6B, 0x2D, 0x73, 0x69, 0x7A, 0x65, 0x20, 0x64,
        0x61, 0x74, 0x61, 0x2E, 0x20, 0x54, 0x68, 0x65,
        0x20, 0x6B, 0x65, 0x79, 0x20, 0x6E, 0x65, 0x65,
        0x64, 0x73, 0x20, 0x74, 0x6F, 0x20, 0x62, 0x65,
        0x20, 0x68, 0x61, 0x73, 0x68, 0x65, 0x64, 0x20,
        0x62, 0x65, 0x66, 0x6F, 0x72, 0x65, 0x20, 0x62,
        0x65, 0x69, 0x6E, 0x67, 0x20, 0x75, 0x73, 0x65,
        0x64, 0x20, 0x62, 0x79, 0x20, 0x74, 0x68, 0x65,
        0x20, 0x48, 0x4D, 0x41, 0x43, 0x20, 0x61, 0x6C,
        0x67, 0x6F, 0x72, 0x69, 0x74, 0x68, 0x6D, 0x2E };
    const ByteBuffer tag {
        0x9B, 0x09, 0xFF, 0xA7, 0x1B, 0x94, 0x2F, 0xCB,
        0x27, 0x63, 0x5F, 0xBC, 0xD5, 0xB0, 0xE9, 0x44
    };
    const KeyTag result(crypto->calculate_hmac_sha256(create_byte_view(key), create_byte_view(msg)).value());
    EXPECT_EQ(create_byte_view(tag), create_byte_view(result.octets));
}

TEST_P(CryptoProviderTest, aes_ccm_decrypts_own_ciphertext)
{
    expected<AesCcmCiphertext> ciphertext = crypto->encrypt_aes_ccm(key, plaintext);
    ASSERT_TRUE(ciphertext.has_value());
    EXPECT_NE(plaintext, ciphertext->ciphertext);
    expected<ByteBuffer> decrypted = crypto->decrypt_aes_ccm(key, *ciphertext);
    ASSERT_TRUE(decrypted.has_value());
    EXPECT_EQ(plaintext, *decrypted);
}

TEST_P(CryptoProviderTest, aes_ccm_encrypts_with_fresh_nonces)
{
    expected<AesCcmCiphertext> first = crypto->encrypt_aes_ccm(key, plaintext);
    expected<AesCcmCiphertext> second = crypto->encrypt_aes_ccm(key, plaintext);
    ASSERT_TRUE(first.has_value());
    ASSERT_TRUE(second.has_value());
    EXPECT_NE(first->nonce, second->nonce);
}

TEST_P(CryptoProviderTest, aes_ccm_rejects_tampered_ciphertext)
{
    expected<AesCcmCiphertext> ciphertext = crypto->encrypt_aes_ccm(key, plaintext);
    ASSERT_TRUE(ciphertext.has_value());

    const struct
    {
        const char* defect;
        void (*tamper)(AesCcmCiphertext&);
    } tamperings[] = {
        { "ciphertext", [](AesCcmCiphertext& c) { c.ciphertext.front() ^= 0x01; } },
        { "authentication tag", [](AesCcmCiphertext& c) { c.ciphertext.back() ^= 0x01; } },
        { "nonce", [](AesCcmCiphertext& c) { c.nonce.front() ^= 0x01; } },
        { "shorter than authentication tag", [](AesCcmCiphertext& c) { c.ciphertext.resize(15); } },
    };

    for (const auto& tampering : tamperings) {
        SCOPED_TRACE(tampering.defect);
        AesCcmCiphertext tampered = *ciphertext;
        tampering.tamper(tampered);
        expected<ByteBuffer> decrypted = crypto->decrypt_aes_ccm(key, tampered);
        ASSERT_TRUE(decrypted.has_error());
        EXPECT_EQ(SecurityModuleError::DecryptionFailure, decrypted.error());
    }
}

// IEEE 1609.2 Annex D.6 AES-CCM test vector
TEST_P(CryptoProviderTest, aes_ccm_decrypts_IEEE_1609_2_Annex_D_6_vector)
{
    const Aes128Key key {{
        0xE5, 0x8D, 0x5C, 0x8F, 0x8C, 0x9E, 0xD9, 0x78, 0x56, 0x79, 0xE0, 0x8A, 0xBC, 0x7C, 0x81, 0x16
    }};
    AesCcmCiphertext encrypted;
    encrypted.nonce = {
        0xA9, 0xF5, 0x93, 0xC0, 0x9E, 0xAE, 0xEA, 0x8B, 0xF0, 0xC1, 0xCF, 0x6A
    };
    encrypted.ciphertext = ByteBuffer {
        0x5F, 0x82, 0xB9, 0xFC, 0xE3, 0x4B, 0x94, 0x83, 0x53, 0x95, 0xDD, 0x89, 0xD7, 0x1F, 0xB7, 0x58,
        0xD2, 0xA3, 0x90, 0x7F, 0xBF, 0x2F, 0xD5, 0x89, 0x94, 0xA2, 0xB9, 0xCF, 0x87, 0x25, 0xAF, 0x26,
        0xF0, 0xB2, 0x38, 0x53, 0xC2, 0x7A, 0x06, 0xE3, 0x5E, 0xE7, 0x2C, 0xAD, 0x82, 0x77, 0x13, 0xC1,
        0x8F, 0xA5, 0xDD, 0xA9, 0x71, 0xD9, 0xBA, 0xA7, 0xB4, 0x2A, 0x30, 0x1F, 0xF6, 0x0C, 0x6E, 0x4A,
        0xD6, 0x51, 0xC1, 0xBB, 0x6E, 0xD4, 0xF2, 0x5F, 0x7D, 0x0F, 0xF3, 0x87, 0xA1, 0x16, 0x27, 0x93,
        0x4C, 0xD1, 0x1F, 0x86, 0x98, 0x4E, 0xA3, 0xAC, 0x96, 0x9D, 0xDA, 0x9A, 0x02, 0x0A, 0xD6, 0x42,
        0x4B, 0x0D, 0x39, 0x3E, 0x3F, 0xB4, 0xB1, 0x11, 0x9A, 0xDF, 0x5C, 0xDB, 0x01, 0x2A, 0x59, 0x75,
        0x3E, 0x41, 0xD4, 0x7E, 0x5E, 0x5A, 0x8C, 0x3A, 0x11, 0x8E, 0xD4, 0x07, 0x04, 0x9B, 0x56, 0xD5,
        0x3B, 0xF5, 0x6C, 0xB3, 0x8C, 0x0B, 0x20, 0xA2, 0x50, 0x2D, 0x1D, 0xA7, 0x0B, 0x97, 0x61
    };
    const ByteBuffer payload {
        0x06, 0x53, 0xB5, 0x71, 0x4D, 0x13, 0x57, 0xF4, 0x99, 0x5B, 0xDD, 0xAC, 0xBE, 0x10, 0x87, 0x39,
        0x51, 0xA1, 0xEB, 0xA6, 0x63, 0x71, 0x8D, 0x1A, 0xF3, 0x5D, 0x2F, 0x0D, 0x52, 0xC7, 0x9D, 0xE4,
        0x9B, 0xE6, 0x22, 0xC4, 0xA6, 0xD9, 0x06, 0x47, 0xBA, 0x2B, 0x00, 0x4C, 0x3E, 0x8A, 0xE4, 0x22,
        0xFD, 0x27, 0x06, 0x3A, 0xFA, 0x19, 0xAD, 0x88, 0x3D, 0xCC, 0xBD, 0x97, 0xD9, 0x8B, 0x8B, 0x04,
        0x61, 0xB5, 0x67, 0x1E, 0x75, 0xF1, 0x97, 0x01, 0xC2, 0x40, 0x42, 0xB8, 0xD3, 0xAF, 0x79, 0xB9,
        0xFF, 0x62, 0xBC, 0x44, 0x8E, 0xF9, 0x44, 0x0B, 0x1E, 0xA3, 0xF7, 0xE5, 0xC0, 0xF4, 0xBF, 0xEF,
        0xE3, 0xE3, 0x26, 0xE6, 0x2D, 0x5E, 0xE4, 0xCB, 0x4B, 0x4C, 0xFF, 0xF3, 0x0A, 0xD5, 0xF4, 0x9A,
        0x79, 0x81, 0xAB, 0xF7, 0x16, 0x17, 0x24, 0x5B, 0x96, 0xE5, 0x22, 0xE1, 0xAD, 0xD7, 0x8A
    };

    expected<ByteBuffer> decrypted = crypto->decrypt_aes_ccm(key, encrypted);
    ASSERT_TRUE(decrypted.has_value());
    EXPECT_EQ(payload, *decrypted);
}

INSTANTIATE_TEST_SUITE_P(Implementations, CryptoProviderTest, ::testing::ValuesIn(builtin_crypto_provider_names()),
    implementation_test_name);

// builds without any crypto provider have nothing to test
GTEST_ALLOW_UNINSTANTIATED_PARAMETERIZED_TEST(CryptoProviderTest);
