#include "openssl_security_module.hpp"
#include "credential_storage.hpp"
#include "openssl.hpp"
#include <vanetza/security/ecies.hpp>
#include <vanetza/security/key_type.hpp>
#include <vanetza/security/public_key.hpp>
#include <openssl/crypto.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <cassert>
#include <stdexcept>

namespace vanetza
{
namespace pki
{

namespace
{

using security::SecurityModuleError;

constexpr std::size_t auth_tag_length = 16;

ByteBuffer calculate_hmac_sha256(const ByteBuffer& key, const ByteBuffer& data)
{
    ByteBuffer hmac;
    hmac.resize(Sha256Hash::length);
    unsigned hmac_len = 0;
    if (!HMAC(EVP_sha256(), key.data(), key.size(), data.data(), data.size(), hmac.data(), &hmac_len)) {
        throw OpenSslException(ERR_get_error(), "HMAC");
    } else if (hmac_len != hmac.size()) {
        throw std::runtime_error("invalid length of HMAC");
    }

    static_assert(Sha256Hash::length >= auth_tag_length, "length of authentication tag exceeds SHA-256 hash");
    hmac.resize(auth_tag_length);
    return hmac;
}

// releases OpenSSL objects, unlike OpenSslPointer a failed allocation yields nullptr instead of an exception
struct OpenSslFree
{
    void operator()(EC_KEY* key) const { EC_KEY_free(key); }
    void operator()(EC_POINT* point) const { EC_POINT_free(point); }
    void operator()(ECDSA_SIG* sig) const { ECDSA_SIG_free(sig); }
    void operator()(EVP_CIPHER_CTX* ctx) const { EVP_CIPHER_CTX_free(ctx); }
};

template<typename T>
using OpenSslPtr = std::unique_ptr<T, OpenSslFree>;

// overwrites secret octets when leaving scope, unlike memset() an OPENSSL_cleanse() is not optimised away
class ScopedCleanse
{
public:
    ScopedCleanse(void* data, std::size_t size) : m_data(data), m_size(size) {}
    ScopedCleanse(const ScopedCleanse&) = delete;
    ScopedCleanse& operator=(const ScopedCleanse&) = delete;
    ~ScopedCleanse() { OPENSSL_cleanse(m_data, m_size); }

private:
    void* m_data;
    std::size_t m_size;
};

KeyType key_type(const EC_KEY* ec_key)
{
    return openssl_nid2key(EC_GROUP_get_curve_name(EC_KEY_get0_group(ec_key)));
}

// our key references are the key type followed by the big-endian private key of key_length() octets
expected<OpenSslPtr<EC_KEY>> build_ec_key(const KeyReference& reference)
{
    const ByteBuffer& data = reference.data;
    const KeyType type = data.empty() ? KeyType::Unspecified : static_cast<KeyType>(data.front());
    const std::size_t length = security::key_length(type); // zero for unsupported key types
    if (length == 0 || data.size() != 1 + length) {
        return make_error_code(SecurityModuleError::InvalidKeyReference);
    }

    OpenSslPtr<EC_KEY> ec_key { EC_KEY_new_by_curve_name(openssl_nid(type)) };
    if (!ec_key || !EC_KEY_oct2priv(ec_key.get(), data.data() + 1, length)) {
        return make_error_code(SecurityModuleError::ModuleFailure);
    }

    // OpenSSL accepts any scalar but only 0 < scalar < order is a private key
    const BIGNUM* scalar = EC_KEY_get0_private_key(ec_key.get());
    const BIGNUM* order = EC_GROUP_get0_order(EC_KEY_get0_group(ec_key.get()));
    if (BN_is_zero(scalar) || BN_cmp(scalar, order) >= 0) {
        return make_error_code(SecurityModuleError::InvalidKeyReference);
    }
    return std::move(ec_key);
}

KeyReference make_key_reference(const PrivateKey& priv)
{
    KeyReference reference;
    reference.data.reserve(1 + priv.key.size());
    reference.data.push_back(static_cast<std::uint8_t>(priv.type));
    reference.data.insert(reference.data.end(), priv.key.begin(), priv.key.end());
    return reference;
}

expected<PublicKey> derive_public_key(const EC_KEY* ec_key)
{
    const EC_GROUP* group = EC_KEY_get0_group(ec_key);
    const BIGNUM* scalar = EC_KEY_get0_private_key(ec_key);
    OpenSslPtr<EC_POINT> point { EC_POINT_new(group) };
    if (!point || !EC_POINT_mul(group, point.get(), scalar, nullptr, nullptr, nullptr)) {
        return make_error_code(SecurityModuleError::ModuleFailure);
    }

    // compressed point: 0x02 (even y) or 0x03 (odd y) followed by x coordinate
    ByteBuffer compressed(1 + (EC_GROUP_get_degree(group) + 7) / 8);
    if (EC_POINT_point2oct(group, point.get(), POINT_CONVERSION_COMPRESSED, compressed.data(), compressed.size(),
            nullptr) != compressed.size()) {
        return make_error_code(SecurityModuleError::ModuleFailure);
    }

    PublicKey pub_key;
    pub_key.type = key_type(ec_key);
    pub_key.compression = compressed.front() == 0x03 ? KeyCompression::Y1 : KeyCompression::Y0;
    pub_key.x.assign(compressed.begin() + 1, compressed.end());
    return pub_key;
}

expected<OpenSslPtr<EC_POINT>> build_ec_point(const EC_GROUP* group, const PublicKey& key)
{
    const ByteBuffer octets = security::encode_ec_point(key);
    if (octets.empty()) {
        return make_error_code(SecurityModuleError::InvalidPublicKey);
    }

    OpenSslPtr<EC_POINT> point { EC_POINT_new(group) };
    if (!point) {
        return make_error_code(SecurityModuleError::ModuleFailure);
    } else if (!EC_POINT_oct2point(group, point.get(), octets.data(), octets.size(), nullptr)) {
        return make_error_code(SecurityModuleError::InvalidPublicKey);
    }
    return std::move(point);
}

// values of EVP_CipherInit_ex's enc argument
enum class CipherOperation : int
{
    Decrypt = 0,
    Encrypt = 1,
};

/**
 * Prepare AES-128-CCM context with key and nonce
 * \param tag expected authentication tag for decryption, nullptr for encryption
 * \return context or nullptr on failure
 */
OpenSslPtr<EVP_CIPHER_CTX> create_aes_ccm_context(CipherOperation operation, const security::Aes128Key& key,
    const std::array<std::uint8_t, AesCcmCiphertext::nonce_length>& nonce, std::uint8_t* tag)
{
    const int enc = static_cast<int>(operation);
    OpenSslPtr<EVP_CIPHER_CTX> ctx { EVP_CIPHER_CTX_new() };
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

OpenSslSecurityModule::OpenSslSecurityModule(std::shared_ptr<CredentialStorage> cred) : m_credential_storage(cred)
{
}

Sha256Hash OpenSslSecurityModule::calculate_sha256_hash(const std::uint8_t* buffer, std::size_t length)
{
    Sha256Hash hash;
    SHA256(buffer, length, hash.octets.data());
    return hash;
}

Sha384Hash OpenSslSecurityModule::calculate_sha384_hash(const std::uint8_t* buffer, std::size_t length)
{
    Sha384Hash hash;
    SHA384(buffer, length, hash.octets.data());
    return hash;
}

bool OpenSslSecurityModule::verify(const Sha256Hash& digest, const Signature& signature, const PublicKey& pubkey)
{
    return verify(digest.octets.data(), digest.octets.size(), signature, pubkey);
}

bool OpenSslSecurityModule::verify(const Sha384Hash& digest, const Signature& signature, const PublicKey& pubkey)
{
    return verify(digest.octets.data(), digest.octets.size(), signature, pubkey);
}

bool OpenSslSecurityModule::verify(const std::uint8_t* dbuf, std::size_t dlen, const Signature& signature,
    const PublicKey& pubkey)
{
    if (signature.type == KeyType::Unspecified || pubkey.type == KeyType::Unspecified) {
        return false;
    } else if (signature.type != pubkey.type) {
        return false;
    } else if (signature.s.empty() || signature.r.empty()) {
        return false;
    }

    OpenSslPointer<EC_KEY> osl_pubkey = make_ec_key(pubkey);
    OpenSslPointer<ECDSA_SIG> osl_sig { ECDSA_SIG_new() };
    BIGNUM* osl_r = BN_bin2bn(signature.r.data(), signature.r.size(), nullptr);
    BIGNUM* osl_s = BN_bin2bn(signature.s.data(), signature.s.size(), nullptr);
    if (!osl_r || !osl_s) {
        BN_free(osl_r); // BN_free(nullptr) is a no-op
        BN_free(osl_s);
        return false;
    }
    // ownership of big numbers is transfered by calling ECDSA_SIG_set0!
    openssl_result(ECDSA_SIG_set0(osl_sig.raw(), osl_r, osl_s), "set signature");
    return (ECDSA_do_verify(dbuf, dlen, osl_sig.raw(), osl_pubkey.raw()) == 1);
}

expected<security::Aes128Key> OpenSslSecurityModule::generate_aes_key()
{
    security::Aes128Key key;
    if (RAND_priv_bytes(key.octets.data(), key.octets.size()) != 1) {
        return make_error_code(SecurityModuleError::ModuleFailure);
    }
    return key;
}

expected<EncryptedSymmetricKey> OpenSslSecurityModule::encrypt_key(
    const PublicKey& recipient, const security::Aes128Key& key, const Sha256Hash& info)
{
    if (security::key_length(recipient.type) == 0) {
        return make_error_code(SecurityModuleError::UnsupportedKeyType);
    }

    OpenSslPtr<EC_KEY> ephemeral { EC_KEY_new_by_curve_name(openssl_nid(recipient.type)) };
    if (!ephemeral || !EC_KEY_generate_key(ephemeral.get())) {
        return make_error_code(SecurityModuleError::ModuleFailure);
    }

    const EC_GROUP* group = EC_KEY_get0_group(ephemeral.get());
    expected<OpenSslPtr<EC_POINT>> recipient_point = build_ec_point(group, recipient);
    if (!recipient_point) {
        return recipient_point.error();
    }

    ByteBuffer shared_secret((EC_GROUP_get_degree(group) + 7) / 8);
    ScopedCleanse cleanse_shared_secret(shared_secret.data(), shared_secret.size());
    if (ECDH_compute_key(shared_secret.data(), shared_secret.size(), recipient_point->get(), ephemeral.get(),
            nullptr) != static_cast<int>(shared_secret.size())) {
        return make_error_code(SecurityModuleError::ModuleFailure);
    }

    expected<PublicKey> ephemeral_public_key = derive_public_key(ephemeral.get());
    if (!ephemeral_public_key) {
        return ephemeral_public_key.error();
    }

    return security::encrypt_key(*ephemeral_public_key, create_byte_view(shared_secret), key, info);
}

expected<AesCcmCiphertext> OpenSslSecurityModule::encrypt_aes_ccm(
    const security::Aes128Key& key, const ByteBuffer& plaintext)
{
    AesCcmCiphertext encrypted;
    if (RAND_bytes(encrypted.nonce.data(), encrypted.nonce.size()) != 1) {
        return make_error_code(SecurityModuleError::ModuleFailure);
    }

    OpenSslPtr<EVP_CIPHER_CTX> ctx = create_aes_ccm_context(CipherOperation::Encrypt, key, encrypted.nonce, nullptr);
    if (!ctx) {
        return make_error_code(SecurityModuleError::ModuleFailure);
    }

    // authentication tag follows the encrypted payload
    encrypted.ciphertext.resize(plaintext.size() + auth_tag_length);
    std::uint8_t* tag = encrypted.ciphertext.data() + plaintext.size();
    int length = 0;
    if (!EVP_EncryptUpdate(ctx.get(), encrypted.ciphertext.data(), &length, plaintext.data(), plaintext.size())) {
        return make_error_code(SecurityModuleError::ModuleFailure);
    }
    assert(static_cast<std::size_t>(length) == plaintext.size());

    // finalisation yields no output for CCM but the tag
    if (!EVP_EncryptFinal_ex(ctx.get(), tag, &length) ||
        !EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_CCM_GET_TAG, auth_tag_length, tag)) {
        return make_error_code(SecurityModuleError::ModuleFailure);
    }
    assert(length == 0);
    return encrypted;
}

expected<ByteBuffer> OpenSslSecurityModule::decrypt_aes_ccm(
    const security::Aes128Key& key, const AesCcmCiphertext& encrypted)
{
    // authentication tag follows the encrypted payload
    if (encrypted.ciphertext.size() < auth_tag_length) {
        return make_error_code(SecurityModuleError::DecryptionFailure);
    }
    ByteBuffer plaintext(encrypted.ciphertext.size() - auth_tag_length);
    std::array<std::uint8_t, auth_tag_length> tag;
    std::copy_n(std::next(encrypted.ciphertext.begin(), plaintext.size()), tag.size(), tag.begin());

    OpenSslPtr<EVP_CIPHER_CTX> ctx = create_aes_ccm_context(CipherOperation::Decrypt, key, encrypted.nonce, tag.data());
    if (!ctx) {
        return make_error_code(SecurityModuleError::ModuleFailure);
    }

    // CCM checks the authentication tag while decrypting
    int length = 0;
    if (EVP_DecryptUpdate(ctx.get(), plaintext.data(), &length, encrypted.ciphertext.data(), plaintext.size()) <= 0) {
        return make_error_code(SecurityModuleError::DecryptionFailure);
    }
    assert(static_cast<std::size_t>(length) == plaintext.size());
    return plaintext;
}

ByteBuffer OpenSslSecurityModule::generate_nonce(std::size_t length)
{
    ByteBuffer nonce;
    nonce.resize(length);
    openssl_result(RAND_bytes(nonce.data(), nonce.size()), "RAND_bytes");
    return nonce;
}

ByteBuffer OpenSslSecurityModule::calculate_hmac_sha256(const ByteBuffer& key, const ByteBuffer& data)
{
    return pki::calculate_hmac_sha256(key, data);
}

expected<KeyReference> OpenSslSecurityModule::create_signing_key(KeyType type)
{
    const std::size_t length = security::key_length(type); // zero for unsupported key types
    if (length == 0) {
        return make_error_code(SecurityModuleError::UnsupportedKeyType);
    }

    OpenSslPtr<EC_KEY> ec_key { EC_KEY_new_by_curve_name(openssl_nid(type)) };
    if (!ec_key || !EC_KEY_generate_key(ec_key.get())) {
        return make_error_code(SecurityModuleError::ModuleFailure);
    }

    PrivateKey priv_key;
    priv_key.type = type;
    priv_key.key.resize(length);
    if (EC_KEY_priv2oct(ec_key.get(), priv_key.key.data(), length) != length) {
        return make_error_code(SecurityModuleError::ModuleFailure);
    }

    expected<PublicKey> pub_key = derive_public_key(ec_key.get());
    if (!pub_key) {
        return pub_key.error();
    }

    try {
        m_credential_storage->store(*pub_key, priv_key);
    } catch (const std::runtime_error&) {
        // credential storage reports failures by exceptions
        return make_error_code(SecurityModuleError::ModuleFailure);
    }
    return make_key_reference(priv_key);
}

expected<KeyReference> OpenSslSecurityModule::find_signing_key(const PublicKey& key)
{
    boost::optional<PrivateKey> priv_key;
    try {
        priv_key = m_credential_storage->fetch(key);
    } catch (const std::runtime_error&) {
        // credential storage reports failures by exceptions
        return make_error_code(SecurityModuleError::ModuleFailure);
    }

    if (!priv_key) {
        return make_error_code(SecurityModuleError::KeyNotFound);
    }

    // credential storage holds signing keys only, thus any valid key is usable for signing
    KeyReference reference = make_key_reference(*priv_key);
    if (!build_ec_key(reference)) {
        return make_error_code(SecurityModuleError::ModuleFailure);
    }
    return reference;
}

expected<PublicKey> OpenSslSecurityModule::public_key(const KeyReference& reference)
{
    expected<OpenSslPtr<EC_KEY>> ec_key = build_ec_key(reference);
    if (ec_key) {
        return derive_public_key(ec_key->get());
    } else {
        return ec_key.error();
    }
}

expected<Signature> OpenSslSecurityModule::sign(const ByteBuffer& digest, const KeyReference& reference)
{
    expected<OpenSslPtr<EC_KEY>> ec_key = build_ec_key(reference);
    if (!ec_key) {
        return ec_key.error();
    }

    OpenSslPtr<ECDSA_SIG> osl_sig { ECDSA_do_sign(digest.data(), digest.size(), ec_key->get()) };
    if (!osl_sig) {
        return make_error_code(SecurityModuleError::ModuleFailure);
    }

    const BIGNUM* osl_r = nullptr;
    const BIGNUM* osl_s = nullptr;
    ECDSA_SIG_get0(osl_sig.get(), &osl_r, &osl_s);
    Signature sig;
    sig.type = key_type(ec_key->get());
    sig.r.resize(BN_num_bytes(osl_r));
    BN_bn2bin(osl_r, sig.r.data());
    sig.s.resize(BN_num_bytes(osl_s));
    BN_bn2bin(osl_s, sig.s.data());
    return sig;
}

bool OpenSslSecurityModule::discard_key(const KeyReference& reference)
{
    expected<OpenSslPtr<EC_KEY>> ec_key = build_ec_key(reference);
    if (!ec_key) {
        return false;
    }
    expected<PublicKey> pub_key = derive_public_key(ec_key->get());
    return pub_key && m_credential_storage->discard(*pub_key);
}

} // namespace pki
} // namespace vanetza
