#include <vanetza/security/psa_crypto_provider.hpp>
#include <vanetza/security/psa_error.hpp>
#include <vanetza/security/psa_wrapper.hpp>
#include <algorithm>
#include <iterator>

namespace vanetza
{
namespace security
{

namespace
{

constexpr std::size_t auth_tag_length = 16;

/**
 * Append big-endian integer with exactly the given length
 * \return false if the integer is missing or its value needs more octets
 */
bool append_integer(ByteBuffer& buffer, const ByteBuffer& integer, std::size_t length)
{
    auto significant = std::find_if(integer.begin(), integer.end(), [](std::uint8_t octet) { return octet != 0; });
    const std::size_t significant_length = std::distance(significant, integer.end());
    if (integer.empty() || significant_length > length) {
        return false;
    }
    buffer.insert(buffer.end(), length - significant_length, 0x00);
    buffer.insert(buffer.end(), significant, integer.end());
    return true;
}

// Import public key for verifying signatures
std::error_code import_verification_key(const PublicKey& public_key, psa_algorithm_t algorithm, psa::Key& key)
{
    const expected<ByteBuffer> point = psa::encode_uncompressed_point(public_key);
    if (!point) {
        return point.error();
    }

    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&attributes, PSA_KEY_TYPE_ECC_PUBLIC_KEY(psa::ecc_family(public_key.type)));
    psa_set_key_bits(&attributes, 8 * key_length(public_key.type));
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_VERIFY_HASH);
    psa_set_key_algorithm(&attributes, algorithm);
    const psa_status_t status = psa_import_key(&attributes, point->data(), point->size(), key.output());
    switch (status) {
        case PSA_SUCCESS:
            return {};
        case PSA_ERROR_NOT_SUPPORTED:
            return make_psa_error(status, SecurityModuleError::UnsupportedKeyType);
        case PSA_ERROR_INVALID_ARGUMENT:
            return make_psa_error(status, SecurityModuleError::InvalidPublicKey);
        default:
            return make_psa_error(status, SecurityModuleError::ModuleFailure);
    }
}

expected<bool> verify_digest(psa_algorithm_t hash_algorithm, const std::uint8_t* digest, std::size_t length,
    const Signature& signature, const PublicKey& public_key)
{
    const std::size_t field_length = key_length(public_key.type);
    if (field_length == 0) {
        return make_error_code(SecurityModuleError::UnsupportedKeyType);
    } else if (signature.type != public_key.type) {
        return false;
    }

    // PSA expects r and s with field length each
    ByteBuffer encoded_signature;
    if (!append_integer(encoded_signature, signature.r, field_length) ||
        !append_integer(encoded_signature, signature.s, field_length)) {
        return false;
    }

    std::error_code error = psa::initialization_error();
    if (error) {
        return error;
    }

    const psa_algorithm_t algorithm = PSA_ALG_ECDSA(hash_algorithm);
    psa::Key key;
    error = import_verification_key(public_key, algorithm, key);
    if (error) {
        return error;
    }

    const psa_status_t status = psa_verify_hash(key.id(), algorithm, digest, length,
        encoded_signature.data(), encoded_signature.size());
    switch (status) {
        case PSA_SUCCESS:
            return true;
        case PSA_ERROR_INVALID_SIGNATURE:
            return false;
        default:
            return make_psa_error(status, SecurityModuleError::ModuleFailure);
    }
}

std::error_code import_aes_ccm_key(const Aes128Key& key, psa_key_usage_t usage, psa::Key& psa_key)
{
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&attributes, PSA_KEY_TYPE_AES);
    psa_set_key_bits(&attributes, 8 * key.octets.size());
    psa_set_key_usage_flags(&attributes, usage);
    psa_set_key_algorithm(&attributes, PSA_ALG_CCM);
    const psa_status_t status = psa_import_key(&attributes, key.octets.data(), key.octets.size(), psa_key.output());
    return status == PSA_SUCCESS ? std::error_code {} : make_psa_error(status, SecurityModuleError::ModuleFailure);
}

} // namespace

Sha256Hash PsaCryptoProvider::calculate_sha256_hash(const std::uint8_t* buffer, std::size_t length)
{
    Sha256Hash hash;
    psa::calculate_hash(PSA_ALG_SHA_256, buffer, length, hash.octets);
    return hash;
}

Sha384Hash PsaCryptoProvider::calculate_sha384_hash(const std::uint8_t* buffer, std::size_t length)
{
    Sha384Hash hash;
    psa::calculate_hash(PSA_ALG_SHA_384, buffer, length, hash.octets);
    return hash;
}

expected<bool> PsaCryptoProvider::verify(const Sha256Hash& digest, const Signature& signature, const PublicKey& key)
{
    return verify_digest(PSA_ALG_SHA_256, digest.octets.data(), digest.octets.size(), signature, key);
}

expected<bool> PsaCryptoProvider::verify(const Sha384Hash& digest, const Signature& signature, const PublicKey& key)
{
    return verify_digest(PSA_ALG_SHA_384, digest.octets.data(), digest.octets.size(), signature, key);
}

expected<AesCcmCiphertext> PsaCryptoProvider::encrypt_aes_ccm(const Aes128Key& key, const ByteBuffer& plaintext)
{
    std::error_code error = psa::initialization_error();
    if (error) {
        return error;
    }

    psa::Key psa_key;
    error = import_aes_ccm_key(key, PSA_KEY_USAGE_ENCRYPT, psa_key);
    if (error) {
        return error;
    }

    AesCcmCiphertext encrypted;
    psa_status_t status = psa_generate_random(encrypted.nonce.data(), encrypted.nonce.size());
    if (status != PSA_SUCCESS) {
        return make_psa_error(status, SecurityModuleError::ModuleFailure);
    }

    // authentication tag follows the encrypted payload
    encrypted.ciphertext.resize(plaintext.size() + auth_tag_length);
    std::size_t length = 0;
    status = psa_aead_encrypt(psa_key.id(), PSA_ALG_CCM, encrypted.nonce.data(), encrypted.nonce.size(), nullptr, 0,
        plaintext.data(), plaintext.size(), encrypted.ciphertext.data(), encrypted.ciphertext.size(), &length);
    if (status != PSA_SUCCESS) {
        return make_psa_error(status, SecurityModuleError::ModuleFailure);
    } else if (length != encrypted.ciphertext.size()) {
        return make_error_code(SecurityModuleError::ModuleFailure);
    }
    return encrypted;
}

expected<ByteBuffer> PsaCryptoProvider::decrypt_aes_ccm(const Aes128Key& key, const AesCcmCiphertext& encrypted)
{
    // authentication tag follows the encrypted payload
    if (encrypted.ciphertext.size() < auth_tag_length) {
        return make_error_code(SecurityModuleError::DecryptionFailure);
    }

    std::error_code error = psa::initialization_error();
    if (error) {
        return error;
    }

    psa::Key psa_key;
    error = import_aes_ccm_key(key, PSA_KEY_USAGE_DECRYPT, psa_key);
    if (error) {
        return error;
    }

    // CCM checks the authentication tag while decrypting
    ByteBuffer plaintext(encrypted.ciphertext.size() - auth_tag_length);
    std::size_t length = 0;
    const psa_status_t status = psa_aead_decrypt(psa_key.id(), PSA_ALG_CCM,
        encrypted.nonce.data(), encrypted.nonce.size(), nullptr, 0,
        encrypted.ciphertext.data(), encrypted.ciphertext.size(), plaintext.data(), plaintext.size(), &length);
    if (status == PSA_ERROR_INVALID_SIGNATURE) {
        return make_psa_error(status, SecurityModuleError::DecryptionFailure);
    } else if (status != PSA_SUCCESS) {
        return make_psa_error(status, SecurityModuleError::ModuleFailure);
    } else if (length != plaintext.size()) {
        return make_error_code(SecurityModuleError::ModuleFailure);
    }
    return plaintext;
}

expected<Sha256Hmac> PsaCryptoProvider::calculate_hmac_sha256(const byte_view_range& key, const byte_view_range& data)
{
    const std::error_code error = psa::initialization_error();
    if (error) {
        return error;
    }

    const psa_algorithm_t algorithm = PSA_ALG_HMAC(PSA_ALG_SHA_256);
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&attributes, PSA_KEY_TYPE_HMAC);
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_SIGN_MESSAGE);
    psa_set_key_algorithm(&attributes, algorithm);
    psa::Key psa_key;
    psa_status_t status = psa_import_key(&attributes, key.data(), key.size(), psa_key.output());
    if (status != PSA_SUCCESS) {
        return make_psa_error(status, SecurityModuleError::ModuleFailure);
    }

    Sha256Hmac hmac;
    std::size_t length = 0;
    status = psa_mac_compute(psa_key.id(), algorithm, data.data(), data.size(),
        hmac.octets.data(), hmac.octets.size(), &length);
    if (status != PSA_SUCCESS) {
        return make_psa_error(status, SecurityModuleError::ModuleFailure);
    } else if (length != hmac.octets.size()) {
        return make_error_code(SecurityModuleError::ModuleFailure);
    }
    return hmac;
}

} // namespace security
} // namespace vanetza
