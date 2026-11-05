#include <vanetza/security/openssl_crypto_provider.hpp>
#include <vanetza/security/openssl_error.hpp>
#include <vanetza/security/openssl_wrapper.hpp>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <array>
#include <cassert>

namespace vanetza
{
namespace security
{

namespace
{

constexpr std::size_t auth_tag_length = 16;

// discards OpenSSL errors queued while in scope, unlike ERR_clear_error() errors queued before are kept
class ScopedErrorMark
{
public:
    ScopedErrorMark() { ERR_set_mark(); }
    ScopedErrorMark(const ScopedErrorMark&) = delete;
    ScopedErrorMark& operator=(const ScopedErrorMark&) = delete;
    ~ScopedErrorMark() { ERR_pop_to_mark(); }
};

// values of EVP_CipherInit_ex's enc argument
enum class CipherOperation : int
{
    Decrypt = 0,
    Encrypt = 1,
};

/**
 * Prepare AES-128-CCM context with key and nonce
 * \param tag expected authentication tag for decryption, nullptr for encryption
 * \return context or nullptr on failure, see OpenSSL's error queue for its reason
 */
openssl::Ptr<EVP_CIPHER_CTX> create_aes_ccm_context(CipherOperation operation, const Aes128Key& key,
    const std::array<std::uint8_t, AesCcmCiphertext::nonce_length>& nonce, std::uint8_t* tag)
{
    const int enc = static_cast<int>(operation);
    openssl::Ptr<EVP_CIPHER_CTX> ctx { EVP_CIPHER_CTX_new() };
    if (!ctx || !EVP_CipherInit_ex(ctx.get(), EVP_aes_128_ccm(), nullptr, nullptr, nullptr, enc)) {
        return nullptr;
    }

    // CCM requires the lengths of nonce and tag before key and nonce
    if (!EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_CCM_SET_IVLEN, nonce.size(), nullptr) ||
        !EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_CCM_SET_TAG, auth_tag_length, tag)) {
        return nullptr;
    }

    if (!EVP_CipherInit_ex(ctx.get(), nullptr, nullptr, key.octets.data(), nonce.data(), enc)) {
        return nullptr;
    }
    return ctx;
}

} // namespace

Sha256Hash OpenSslCryptoProvider::calculate_sha256_hash(const std::uint8_t* buffer, std::size_t length)
{
    Sha256Hash hash;
    SHA256(buffer, length, hash.octets.data());
    return hash;
}

Sha384Hash OpenSslCryptoProvider::calculate_sha384_hash(const std::uint8_t* buffer, std::size_t length)
{
    Sha384Hash hash;
    SHA384(buffer, length, hash.octets.data());
    return hash;
}

expected<bool> OpenSslCryptoProvider::verify(
    const Sha256Hash& digest, const Signature& signature, const PublicKey& pubkey)
{
    return verify(digest.octets.data(), digest.octets.size(), signature, pubkey);
}

expected<bool> OpenSslCryptoProvider::verify(
    const Sha384Hash& digest, const Signature& signature, const PublicKey& pubkey)
{
    return verify(digest.octets.data(), digest.octets.size(), signature, pubkey);
}

expected<bool> OpenSslCryptoProvider::verify(
    const std::uint8_t* dbuf, std::size_t dlen, const Signature& signature, const PublicKey& pubkey)
{
    if (key_length(pubkey.type) == 0) {
        return make_error_code(SecurityModuleError::UnsupportedKeyType);
    } else if (signature.type != pubkey.type) {
        return false;
    } else if (signature.s.empty() || signature.r.empty()) {
        return false;
    }

    // a non-matching signature is no error, verify() discards OpenSSL's entries for it, e.g. r or s out of range
    ScopedErrorMark discard_errors;

    openssl::Ptr<EC_KEY> ec_key { EC_KEY_new_by_curve_name(openssl::nid(pubkey.type)) };
    if (!ec_key) {
        return take_openssl_error(SecurityModuleError::ModuleFailure);
    }

    openssl::Ptr<EC_POINT> point = openssl::build_point(EC_KEY_get0_group(ec_key.get()), pubkey);
    if (!point) {
        return take_openssl_error(SecurityModuleError::InvalidPublicKey);
    } else if (!EC_KEY_set_public_key(ec_key.get(), point.get())) {
        return take_openssl_error(SecurityModuleError::ModuleFailure);
    }

    openssl::Ptr<ECDSA_SIG> osl_sig { ECDSA_SIG_new() };
    openssl::Ptr<BIGNUM> osl_r { BN_bin2bn(signature.r.data(), signature.r.size(), nullptr) };
    openssl::Ptr<BIGNUM> osl_s { BN_bin2bn(signature.s.data(), signature.s.size(), nullptr) };
    if (!osl_sig || !osl_r || !osl_s) {
        return take_openssl_error(SecurityModuleError::ModuleFailure);
    } else if (!ECDSA_SIG_set0(osl_sig.get(), osl_r.get(), osl_s.get())) {
        return take_openssl_error(SecurityModuleError::ModuleFailure);
    }
    // signature owns the big numbers after ECDSA_SIG_set0
    osl_r.release();
    osl_s.release();

    // ECDSA_do_verify returns -1 if it fails to tell valid and invalid signatures apart
    switch (ECDSA_do_verify(dbuf, dlen, osl_sig.get(), ec_key.get())) {
        case 1:
            return true;
        case 0:
            return false;
        default:
            return take_openssl_error(SecurityModuleError::ModuleFailure);
    }
}

expected<AesCcmCiphertext> OpenSslCryptoProvider::encrypt_aes_ccm(
    const Aes128Key& key, const ByteBuffer& plaintext)
{
    AesCcmCiphertext encrypted;
    if (RAND_bytes(encrypted.nonce.data(), encrypted.nonce.size()) != 1) {
        return take_openssl_error(SecurityModuleError::ModuleFailure);
    }

    openssl::Ptr<EVP_CIPHER_CTX> ctx = create_aes_ccm_context(CipherOperation::Encrypt, key, encrypted.nonce, nullptr);
    if (!ctx) {
        return take_openssl_error(SecurityModuleError::ModuleFailure);
    }

    // authentication tag follows the encrypted payload
    encrypted.ciphertext.resize(plaintext.size() + auth_tag_length);
    std::uint8_t* tag = encrypted.ciphertext.data() + plaintext.size();
    int length = 0;
    if (!EVP_EncryptUpdate(ctx.get(), encrypted.ciphertext.data(), &length, plaintext.data(), plaintext.size())) {
        return take_openssl_error(SecurityModuleError::ModuleFailure);
    }
    assert(static_cast<std::size_t>(length) == plaintext.size());

    // finalisation yields no output for CCM but the tag
    if (!EVP_EncryptFinal_ex(ctx.get(), tag, &length) ||
        !EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_CCM_GET_TAG, auth_tag_length, tag)) {
        return take_openssl_error(SecurityModuleError::ModuleFailure);
    }
    assert(length == 0);
    return encrypted;
}

expected<ByteBuffer> OpenSslCryptoProvider::decrypt_aes_ccm(
    const Aes128Key& key, const AesCcmCiphertext& encrypted)
{
    // authentication tag follows the encrypted payload
    if (encrypted.ciphertext.size() < auth_tag_length) {
        return make_error_code(SecurityModuleError::DecryptionFailure);
    }
    ByteBuffer plaintext(encrypted.ciphertext.size() - auth_tag_length);
    std::array<std::uint8_t, auth_tag_length> tag;
    std::copy_n(std::next(encrypted.ciphertext.begin(), plaintext.size()), tag.size(), tag.begin());

    openssl::Ptr<EVP_CIPHER_CTX> ctx = create_aes_ccm_context(CipherOperation::Decrypt, key, encrypted.nonce, tag.data());
    if (!ctx) {
        return take_openssl_error(SecurityModuleError::ModuleFailure);
    }

    // CCM checks the authentication tag while decrypting
    int length = 0;
    if (EVP_DecryptUpdate(ctx.get(), plaintext.data(), &length, encrypted.ciphertext.data(), plaintext.size()) <= 0) {
        return take_openssl_error(SecurityModuleError::DecryptionFailure);
    }
    assert(static_cast<std::size_t>(length) == plaintext.size());
    return plaintext;
}

expected<Sha256Hmac> OpenSslCryptoProvider::calculate_hmac_sha256(
    const byte_view_range& key, const byte_view_range& data)
{
    Sha256Hmac hmac;
    unsigned length = 0;
    if (!HMAC(EVP_sha256(), key.data(), key.size(), data.data(), data.size(), hmac.octets.data(), &length)) {
        return take_openssl_error(SecurityModuleError::ModuleFailure);
    } else if (length != hmac.octets.size()) {
        return make_error_code(SecurityModuleError::ModuleFailure);
    }
    return hmac;
}

} // namespace security
} // namespace vanetza
