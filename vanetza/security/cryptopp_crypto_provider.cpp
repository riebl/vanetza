#include <vanetza/security/cryptopp_crypto_provider.hpp>
#include <vanetza/security/cryptopp_wrapper.hpp>
#include <cryptopp/aes.h>
#include <cryptopp/ccm.h>
#include <cryptopp/hmac.h>
#include <cryptopp/sha.h>

namespace vanetza
{
namespace security
{

namespace
{

constexpr std::size_t auth_tag_length = 16;

using AesCcm = CryptoPP::CCM<CryptoPP::AES, auth_tag_length>;

} // namespace

Sha256Hash CryptoppCryptoProvider::calculate_sha256_hash(const std::uint8_t* buffer, std::size_t length)
{
    Sha256Hash hash;
    CryptoPP::SHA256().CalculateDigest(hash.octets.data(), buffer, length);
    return hash;
}

Sha384Hash CryptoppCryptoProvider::calculate_sha384_hash(const std::uint8_t* buffer, std::size_t length)
{
    Sha384Hash hash;
    CryptoPP::SHA384().CalculateDigest(hash.octets.data(), buffer, length);
    return hash;
}

expected<bool> CryptoppCryptoProvider::verify(
    const Sha256Hash& digest, const Signature& signature, const PublicKey& pubkey)
{
    return verify(digest.octets.data(), digest.octets.size(), signature, pubkey);
}

expected<bool> CryptoppCryptoProvider::verify(
    const Sha384Hash& digest, const Signature& signature, const PublicKey& pubkey)
{
    return verify(digest.octets.data(), digest.octets.size(), signature, pubkey);
}

expected<bool> CryptoppCryptoProvider::verify(
    const std::uint8_t* digest, std::size_t length, const Signature& signature, const PublicKey& pubkey)
{
    if (key_length(pubkey.type) == 0) {
        return make_error_code(SecurityModuleError::UnsupportedKeyType);
    } else if (signature.type != pubkey.type) {
        return false;
    }

    const boost::optional<cryptopp::EcPublicKey> key = cryptopp::convert_public_key(pubkey);
    if (!key || !key->GetGroupParameters().ValidateElement(1, key->GetPublicElement(), nullptr)) {
        return make_error_code(SecurityModuleError::InvalidPublicKey);
    }

    const CryptoPP::Integer e = cryptopp::digest_integer(digest, length, key->GetGroupParameters().GetSubgroupOrder());
    const CryptoPP::Integer r { signature.r.data(), signature.r.size() };
    const CryptoPP::Integer s { signature.s.data(), signature.s.size() };
    return CryptoPP::DL_Algorithm_ECDSA<CryptoPP::ECP>().Verify(key->GetGroupParameters(), *key, e, r, s);
}

expected<AesCcmCiphertext> CryptoppCryptoProvider::encrypt_aes_ccm(
    const Aes128Key& key, const ByteBuffer& plaintext)
{
    AesCcmCiphertext encrypted;
    if (!cryptopp::generate_random(encrypted.nonce.data(), encrypted.nonce.size())) {
        return make_error_code(SecurityModuleError::ModuleFailure);
    }

    // authentication tag follows the encrypted payload
    encrypted.ciphertext.resize(plaintext.size() + auth_tag_length);
    AesCcm::Encryption aes;
    aes.SetKeyWithIV(key.octets.data(), key.octets.size(), encrypted.nonce.data(), encrypted.nonce.size());
    aes.EncryptAndAuthenticate(encrypted.ciphertext.data(), encrypted.ciphertext.data() + plaintext.size(),
        auth_tag_length, encrypted.nonce.data(), encrypted.nonce.size(), nullptr, 0,
        plaintext.data(), plaintext.size());
    return encrypted;
}

expected<ByteBuffer> CryptoppCryptoProvider::decrypt_aes_ccm(
    const Aes128Key& key, const AesCcmCiphertext& encrypted)
{
    // authentication tag follows the encrypted payload
    if (encrypted.ciphertext.size() < auth_tag_length) {
        return make_error_code(SecurityModuleError::DecryptionFailure);
    }
    ByteBuffer plaintext(encrypted.ciphertext.size() - auth_tag_length);

    AesCcm::Decryption aes;
    aes.SetKeyWithIV(key.octets.data(), key.octets.size(), encrypted.nonce.data(), encrypted.nonce.size());
    if (!aes.DecryptAndVerify(plaintext.data(), encrypted.ciphertext.data() + plaintext.size(), auth_tag_length,
            encrypted.nonce.data(), encrypted.nonce.size(), nullptr, 0,
            encrypted.ciphertext.data(), plaintext.size())) {
        return make_error_code(SecurityModuleError::DecryptionFailure);
    }
    return plaintext;
}

expected<Sha256Hmac> CryptoppCryptoProvider::calculate_hmac_sha256(
    const byte_view_range& key, const byte_view_range& data)
{
    Sha256Hmac hmac;
    CryptoPP::HMAC<CryptoPP::SHA256>(key.data(), key.size()).CalculateDigest(
        hmac.octets.data(), data.data(), data.size());
    return hmac;
}

} // namespace security
} // namespace vanetza
