#include <vanetza/security/credential_storage.hpp>
#include <vanetza/security/ecies.hpp>
#include <vanetza/security/key_type.hpp>
#include <vanetza/security/openssl_error.hpp>
#include <vanetza/security/openssl_security_module.hpp>
#include <vanetza/security/public_key.hpp>
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/ec.h>
#include <openssl/ecdh.h>
#include <openssl/ecdsa.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <array>
#include <memory>
#include <cassert>
#include <stdexcept>

namespace vanetza
{
namespace security
{

namespace
{

constexpr std::size_t auth_tag_length = 16;

// releases OpenSSL objects, unlike openssl::Key a failed allocation yields nullptr instead of an exception
struct OpenSslFree
{
    void operator()(BIGNUM* bn) const { BN_free(bn); }
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

// discards OpenSSL errors queued while in scope, unlike ERR_clear_error() errors queued before are kept
class ScopedErrorMark
{
public:
    ScopedErrorMark() { ERR_set_mark(); }
    ScopedErrorMark(const ScopedErrorMark&) = delete;
    ScopedErrorMark& operator=(const ScopedErrorMark&) = delete;
    ~ScopedErrorMark() { ERR_pop_to_mark(); }
};

int openssl_nid(KeyType key)
{
    int nid = 0;
    switch (key) {
        case KeyType::NistP256:
            nid = NID_X9_62_prime256v1;
            break;
        case KeyType::BrainpoolP256r1:
            nid = NID_brainpoolP256r1;
            break;
        case KeyType::BrainpoolP384r1:
            nid = NID_brainpoolP384r1;
            break;
        default:
            throw std::runtime_error("unknown key type");
            break;
    }
    return nid;
}

KeyType openssl_nid2key(int nid)
{
    switch (nid) {
        case NID_X9_62_prime256v1:
            return KeyType::NistP256;
            break;
        case NID_brainpoolP256r1:
            return KeyType::BrainpoolP256r1;
            break;
        case NID_brainpoolP384r1:
            return KeyType::BrainpoolP384r1;
            break;
        default:
            throw std::runtime_error("unsupported curve type");
            break;
    }
}

KeyType key_type(const EC_KEY* ec_key)
{
    return openssl_nid2key(EC_GROUP_get_curve_name(EC_KEY_get0_group(ec_key)));
}

// our key references are the key type followed by the big-endian private key of key_length() octets
expected<OpenSslPtr<EC_KEY>> build_ec_key(const KeyReference& reference)
{
    const ByteBuffer& data = reference.data;
    const KeyType type = data.empty() ? KeyType::Unspecified : static_cast<KeyType>(data.front());
    const std::size_t length = key_length(type); // zero for unsupported key types
    if (length == 0 || data.size() != 1 + length) {
        return make_error_code(SecurityModuleError::InvalidKeyReference);
    }

    OpenSslPtr<EC_KEY> ec_key { EC_KEY_new_by_curve_name(openssl_nid(type)) };
    if (!ec_key || !EC_KEY_oct2priv(ec_key.get(), data.data() + 1, length)) {
        return take_openssl_error(SecurityModuleError::ModuleFailure);
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
        return take_openssl_error(SecurityModuleError::ModuleFailure);
    }

    // compressed point: 0x02 (even y) or 0x03 (odd y) followed by x coordinate
    ByteBuffer compressed(1 + (EC_GROUP_get_degree(group) + 7) / 8);
    if (EC_POINT_point2oct(group, point.get(), POINT_CONVERSION_COMPRESSED, compressed.data(), compressed.size(),
            nullptr) != compressed.size()) {
        return take_openssl_error(SecurityModuleError::ModuleFailure);
    }

    PublicKey pub_key;
    pub_key.type = key_type(ec_key);
    pub_key.compression = compressed.front() == 0x03 ? KeyCompression::Y1 : KeyCompression::Y0;
    pub_key.x.assign(compressed.begin() + 1, compressed.end());
    return pub_key;
}

/**
 * Build elliptic curve point of a public key
 * \return point or nullptr on failure, see OpenSSL's error queue for its reason
 */
OpenSslPtr<EC_POINT> build_ec_point(const EC_GROUP* group, const PublicKey& key)
{
    const ByteBuffer octets = encode_ec_point(key);
    if (octets.empty()) {
        return nullptr;
    }

    // unlike EC_POINT_set_*_coordinates, EC_POINT_oct2point rejects coordinates exceeding the field
    OpenSslPtr<EC_POINT> point { EC_POINT_new(group) };
    if (!point || !EC_POINT_oct2point(group, point.get(), octets.data(), octets.size(), nullptr)) {
        return nullptr;
    }
    return point;
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
 * \return context or nullptr on failure, see OpenSSL's error queue for its reason
 */
OpenSslPtr<EVP_CIPHER_CTX> create_aes_ccm_context(CipherOperation operation, const Aes128Key& key,
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

expected<bool> OpenSslSecurityModule::verify(
    const Sha256Hash& digest, const Signature& signature, const PublicKey& pubkey)
{
    return verify(digest.octets.data(), digest.octets.size(), signature, pubkey);
}

expected<bool> OpenSslSecurityModule::verify(
    const Sha384Hash& digest, const Signature& signature, const PublicKey& pubkey)
{
    return verify(digest.octets.data(), digest.octets.size(), signature, pubkey);
}

expected<bool> OpenSslSecurityModule::verify(
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

    OpenSslPtr<EC_KEY> ec_key { EC_KEY_new_by_curve_name(openssl_nid(pubkey.type)) };
    if (!ec_key) {
        return take_openssl_error(SecurityModuleError::ModuleFailure);
    }

    OpenSslPtr<EC_POINT> point = build_ec_point(EC_KEY_get0_group(ec_key.get()), pubkey);
    if (!point) {
        return take_openssl_error(SecurityModuleError::InvalidPublicKey);
    } else if (!EC_KEY_set_public_key(ec_key.get(), point.get())) {
        return take_openssl_error(SecurityModuleError::ModuleFailure);
    }

    OpenSslPtr<ECDSA_SIG> osl_sig { ECDSA_SIG_new() };
    OpenSslPtr<BIGNUM> osl_r { BN_bin2bn(signature.r.data(), signature.r.size(), nullptr) };
    OpenSslPtr<BIGNUM> osl_s { BN_bin2bn(signature.s.data(), signature.s.size(), nullptr) };
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

expected<Aes128Key> OpenSslSecurityModule::generate_aes_key()
{
    Aes128Key key;
    if (RAND_priv_bytes(key.octets.data(), key.octets.size()) != 1) {
        return take_openssl_error(SecurityModuleError::ModuleFailure);
    }
    return key;
}

expected<HmacKey> OpenSslSecurityModule::generate_hmac_key()
{
    HmacKey key;
    if (RAND_priv_bytes(key.octets.data(), key.octets.size()) != 1) {
        return take_openssl_error(SecurityModuleError::ModuleFailure);
    }
    return key;
}

expected<EncryptedSymmetricKey> OpenSslSecurityModule::encrypt_key(
    const PublicKey& recipient, const Aes128Key& key, const Sha256Hash& info)
{
    if (key_length(recipient.type) == 0) {
        return make_error_code(SecurityModuleError::UnsupportedKeyType);
    }

    OpenSslPtr<EC_KEY> ephemeral { EC_KEY_new_by_curve_name(openssl_nid(recipient.type)) };
    if (!ephemeral || !EC_KEY_generate_key(ephemeral.get())) {
        return take_openssl_error(SecurityModuleError::ModuleFailure);
    }

    const EC_GROUP* group = EC_KEY_get0_group(ephemeral.get());
    OpenSslPtr<EC_POINT> recipient_point = build_ec_point(group, recipient);
    if (!recipient_point) {
        return take_openssl_error(SecurityModuleError::InvalidPublicKey);
    }

    ByteBuffer shared_secret((EC_GROUP_get_degree(group) + 7) / 8);
    ScopedCleanse cleanse_shared_secret(shared_secret.data(), shared_secret.size());
    if (ECDH_compute_key(shared_secret.data(), shared_secret.size(), recipient_point.get(), ephemeral.get(), nullptr) !=
        static_cast<int>(shared_secret.size())) {
        return take_openssl_error(SecurityModuleError::ModuleFailure);
    }

    expected<PublicKey> ephemeral_public_key = derive_public_key(ephemeral.get());
    if (!ephemeral_public_key) {
        return ephemeral_public_key.error();
    }

    return security::encrypt_key(*this, *ephemeral_public_key, create_byte_view(shared_secret), key, info);
}

expected<AesCcmCiphertext> OpenSslSecurityModule::encrypt_aes_ccm(
    const Aes128Key& key, const ByteBuffer& plaintext)
{
    AesCcmCiphertext encrypted;
    if (RAND_bytes(encrypted.nonce.data(), encrypted.nonce.size()) != 1) {
        return take_openssl_error(SecurityModuleError::ModuleFailure);
    }

    OpenSslPtr<EVP_CIPHER_CTX> ctx = create_aes_ccm_context(CipherOperation::Encrypt, key, encrypted.nonce, nullptr);
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

expected<ByteBuffer> OpenSslSecurityModule::decrypt_aes_ccm(
    const Aes128Key& key, const AesCcmCiphertext& encrypted)
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

expected<Sha256Hmac> OpenSslSecurityModule::calculate_hmac_sha256(
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

expected<KeyReference> OpenSslSecurityModule::create_signing_key(KeyType type)
{
    const std::size_t length = key_length(type); // zero for unsupported key types
    if (length == 0) {
        return make_error_code(SecurityModuleError::UnsupportedKeyType);
    }

    OpenSslPtr<EC_KEY> ec_key { EC_KEY_new_by_curve_name(openssl_nid(type)) };
    if (!ec_key || !EC_KEY_generate_key(ec_key.get())) {
        return take_openssl_error(SecurityModuleError::ModuleFailure);
    }

    PrivateKey priv_key;
    priv_key.type = type;
    priv_key.key.resize(length);
    if (EC_KEY_priv2oct(ec_key.get(), priv_key.key.data(), length) != length) {
        return take_openssl_error(SecurityModuleError::ModuleFailure);
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
        return take_openssl_error(SecurityModuleError::ModuleFailure);
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

} // namespace security
} // namespace vanetza
