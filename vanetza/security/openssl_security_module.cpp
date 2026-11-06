#include <vanetza/security/credential_storage.hpp>
#include <vanetza/security/ecies.hpp>
#include <vanetza/security/key_type.hpp>
#include <vanetza/security/openssl_crypto_provider.hpp>
#include <vanetza/security/openssl_error.hpp>
#include <vanetza/security/openssl_security_module.hpp>
#include <vanetza/security/openssl_wrapper.hpp>
#include <vanetza/security/public_key.hpp>
#include <openssl/bn.h>
#include <openssl/crypto.h>
#include <openssl/ec.h>
#include <openssl/ecdh.h>
#include <openssl/ecdsa.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
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
expected<openssl::Ptr<EC_KEY>> build_ec_key(const KeyReference& reference)
{
    const ByteBuffer& data = reference.data;
    const KeyType type = data.empty() ? KeyType::Unspecified : static_cast<KeyType>(data.front());
    const std::size_t length = key_length(type); // zero for unsupported key types
    if (length == 0 || data.size() != 1 + length) {
        return make_error_code(SecurityModuleError::InvalidKeyReference);
    }

    openssl::Ptr<EC_KEY> ec_key { EC_KEY_new_by_curve_name(openssl::nid(type)) };
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
    openssl::Ptr<EC_POINT> point { EC_POINT_new(group) };
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
} // namespace

OpenSslSecurityModule::OpenSslSecurityModule(std::shared_ptr<CredentialStorage> cred) : m_credential_storage(cred)
{
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

    openssl::Ptr<EC_KEY> ephemeral { EC_KEY_new_by_curve_name(openssl::nid(recipient.type)) };
    if (!ephemeral || !EC_KEY_generate_key(ephemeral.get())) {
        return take_openssl_error(SecurityModuleError::ModuleFailure);
    }

    const EC_GROUP* group = EC_KEY_get0_group(ephemeral.get());
    openssl::Ptr<EC_POINT> recipient_point = openssl::build_point(group, recipient);
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

    // this software module derives keys and tag with OpenSSL like an HSM does internally
    OpenSslCryptoProvider crypto;
    return security::encrypt_key(crypto, *ephemeral_public_key, create_byte_view(shared_secret), key, info);
}

expected<KeyReference> OpenSslSecurityModule::create_signing_key(KeyType type)
{
    const std::size_t length = key_length(type); // zero for unsupported key types
    if (length == 0) {
        return make_error_code(SecurityModuleError::UnsupportedKeyType);
    }

    openssl::Ptr<EC_KEY> ec_key { EC_KEY_new_by_curve_name(openssl::nid(type)) };
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

    if (m_credential_storage) {
        try {
            m_credential_storage->store(*pub_key, priv_key);
        } catch (const std::runtime_error&) {
            // credential storage reports failures by exceptions
            return make_error_code(SecurityModuleError::ModuleFailure);
        }
    }
    return make_key_reference(priv_key);
}

expected<KeyReference> OpenSslSecurityModule::find_signing_key(const PublicKey& key)
{
    if (!m_credential_storage) {
        return make_error_code(SecurityModuleError::KeyNotFound);
    }

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
    expected<openssl::Ptr<EC_KEY>> ec_key = build_ec_key(reference);
    if (ec_key) {
        return derive_public_key(ec_key->get());
    } else {
        return ec_key.error();
    }
}

expected<Signature> OpenSslSecurityModule::sign(const ByteBuffer& digest, const KeyReference& reference)
{
    expected<openssl::Ptr<EC_KEY>> ec_key = build_ec_key(reference);
    if (!ec_key) {
        return ec_key.error();
    }

    openssl::Ptr<ECDSA_SIG> osl_sig { ECDSA_do_sign(digest.data(), digest.size(), ec_key->get()) };
    if (!osl_sig) {
        return take_openssl_error(SecurityModuleError::ModuleFailure);
    }

    const BIGNUM* osl_r = nullptr;
    const BIGNUM* osl_s = nullptr;
    ECDSA_SIG_get0(osl_sig.get(), &osl_r, &osl_s);
    Signature sig;
    sig.type = key_type(ec_key->get());
    const std::size_t length = key_length(sig.type);
    sig.r.resize(length);
    sig.s.resize(length);
    if (BN_bn2binpad(osl_r, sig.r.data(), length) < 0 || BN_bn2binpad(osl_s, sig.s.data(), length) < 0) {
        return take_openssl_error(SecurityModuleError::ModuleFailure);
    }
    return sig;
}

bool OpenSslSecurityModule::discard_key(const KeyReference& reference)
{
    expected<openssl::Ptr<EC_KEY>> ec_key = build_ec_key(reference);
    if (!ec_key) {
        return false;
    }
    expected<PublicKey> pub_key = derive_public_key(ec_key->get());
    // without credential storage there are no module resources to release
    return pub_key && (!m_credential_storage || m_credential_storage->discard(*pub_key));
}

} // namespace security
} // namespace vanetza
