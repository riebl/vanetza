#include <vanetza/security/ecies.hpp>
#include <vanetza/security/psa_crypto_provider.hpp>
#include <vanetza/security/psa_error.hpp>
#include <vanetza/security/psa_security_module.hpp>
#include <vanetza/security/psa_wrapper.hpp>
#include <vanetza/security/public_key.hpp>
#include <array>
#include <string>

namespace vanetza
{
namespace security
{

namespace
{

constexpr std::size_t key_reference_length = 4;

// another key may occupy the identifier derived from a fresh key pair's public key
constexpr unsigned key_creation_attempts = 4;

// overwrites secret octets when leaving scope, volatile writes are not optimised away
class ScopedWipe
{
public:
    explicit ScopedWipe(ByteBuffer& buffer) : m_buffer(buffer) {}
    ScopedWipe(const ScopedWipe&) = delete;
    ScopedWipe& operator=(const ScopedWipe&) = delete;

    ~ScopedWipe()
    {
        volatile std::uint8_t* octet = m_buffer.data();
        for (std::size_t i = 0; i < m_buffer.size(); ++i) {
            octet[i] = 0;
        }
    }

private:
    ByteBuffer& m_buffer;
};

KeyReference make_key_reference(psa_key_id_t id)
{
    KeyReference reference;
    for (std::size_t i = key_reference_length; i > 0; --i) {
        reference.data.push_back(static_cast<std::uint8_t>(id >> (8 * (i - 1))));
    }
    return reference;
}

expected<psa_key_id_t> key_id(const KeyReference& reference)
{
    if (reference.data.size() != key_reference_length) {
        return make_error_code(SecurityModuleError::InvalidKeyReference);
    }

    psa_key_id_t id = 0;
    for (std::uint8_t octet : reference.data) {
        id = (id << 8) | octet;
    }
    if (id < PSA_KEY_ID_USER_MIN || id > PSA_KEY_ID_USER_MAX) {
        return make_error_code(SecurityModuleError::InvalidKeyReference);
    }
    return id;
}

/**
 * Derive persistent key identifier from a public key
 * \param name canonical hex string of public key
 * \return 30 bits of SHA-256 over name, i.e. an identifier of the user range or null identifier
 */
expected<psa_key_id_t> derive_key_id(const std::string& name)
{
    std::array<std::uint8_t, 32> digest;
    std::size_t length = 0;
    const psa_status_t status = psa_hash_compute(PSA_ALG_SHA_256, reinterpret_cast<const std::uint8_t*>(name.data()),
        name.size(), digest.data(), digest.size(), &length);
    if (status != PSA_SUCCESS) {
        return make_psa_error(status, SecurityModuleError::ModuleFailure);
    } else if (length != digest.size()) {
        return make_error_code(SecurityModuleError::ModuleFailure);
    }

    psa_key_id_t id = 0;
    for (std::size_t i = 0; i < key_reference_length; ++i) {
        id = (id << 8) | digest[i];
    }
    return id & PSA_KEY_ID_USER_MAX;
}

/**
 * Get key type of a signing key created by this module
 * \param unusable condition if there is no such key, e.g. a foreign key with other purpose
 * \return key type or error
 */
expected<KeyType> signing_key_type(psa_key_id_t id, SecurityModuleError unusable)
{
    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    const psa_status_t status = psa_get_key_attributes(id, &attributes);
    if (status == PSA_ERROR_INVALID_HANDLE || status == PSA_ERROR_DOES_NOT_EXIST) {
        return make_psa_error(status, unusable);
    } else if (status != PSA_SUCCESS) {
        return make_psa_error(status, SecurityModuleError::ModuleFailure);
    }

    const psa_key_type_t type = psa_get_key_type(&attributes);
    const std::size_t bits = psa_get_key_bits(&attributes);
    const bool signing = (psa_get_key_usage_flags(&attributes) & PSA_KEY_USAGE_SIGN_HASH) &&
        psa_get_key_algorithm(&attributes) == PSA_ALG_ECDSA_ANY;
    psa_reset_key_attributes(&attributes);

    if (signing && PSA_KEY_TYPE_IS_ECC_KEY_PAIR(type)) {
        for (KeyType candidate : { KeyType::NistP256, KeyType::BrainpoolP256r1, KeyType::BrainpoolP384r1 }) {
            if (PSA_KEY_TYPE_ECC_GET_FAMILY(type) == psa::ecc_family(candidate) &&
                bits == 8 * key_length(candidate)) {
                return candidate;
            }
        }
    }
    return make_error_code(unusable);
}

expected<PublicKey> export_public_key(psa_key_id_t id, KeyType type)
{
    const std::size_t length = key_length(type);
    ByteBuffer point(1 + 2 * length);
    std::size_t point_length = 0;
    const psa_status_t status = psa_export_public_key(id, point.data(), point.size(), &point_length);
    if (status != PSA_SUCCESS) {
        return make_psa_error(status, SecurityModuleError::ModuleFailure);
    } else if (point_length != point.size() || point.front() != 0x04) {
        return make_error_code(SecurityModuleError::ModuleFailure);
    }

    // compressed form like certificates carry their keys
    PublicKey key;
    key.type = type;
    key.compression = point.back() % 2 == 0 ? KeyCompression::Y0 : KeyCompression::Y1;
    key.x.assign(point.begin() + 1, point.begin() + 1 + length);
    return key;
}

} // namespace

expected<KeyReference> PsaSecurityModule::create_signing_key(KeyType type)
{
    const psa_ecc_family_t family = psa::ecc_family(type);
    if (family == 0) {
        return make_error_code(SecurityModuleError::UnsupportedKeyType);
    }

    const std::error_code error = psa::initialization_error();
    if (error) {
        return error;
    }

    for (unsigned attempt = 0; attempt < key_creation_attempts; ++attempt) {
        // the identifier derives from the public key, which exists only after generating a key pair
        psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
        psa_set_key_type(&attributes, PSA_KEY_TYPE_ECC_KEY_PAIR(family));
        psa_set_key_bits(&attributes, 8 * key_length(type));
        psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_SIGN_HASH | PSA_KEY_USAGE_COPY);
        psa_set_key_algorithm(&attributes, PSA_ALG_ECDSA_ANY);
        psa::Key transient;
        psa_status_t status = psa_generate_key(&attributes, transient.output());
        if (status == PSA_ERROR_NOT_SUPPORTED) {
            return make_psa_error(status, SecurityModuleError::UnsupportedKeyType);
        } else if (status != PSA_SUCCESS) {
            return make_psa_error(status, SecurityModuleError::ModuleFailure);
        }

        const expected<PublicKey> public_key = export_public_key(transient.id(), type);
        if (!public_key) {
            return public_key.error();
        }
        const expected<psa_key_id_t> id = derive_key_id(canonical_hexstring(*public_key));
        if (!id) {
            return id.error();
        } else if (*id == PSA_KEY_ID_NULL) {
            continue;
        }

        // the stored key is neither copyable nor exportable
        psa_key_attributes_t persistent = PSA_KEY_ATTRIBUTES_INIT;
        psa_set_key_id(&persistent, *id);
        psa_set_key_usage_flags(&persistent, PSA_KEY_USAGE_SIGN_HASH);
        psa_set_key_algorithm(&persistent, PSA_ALG_ECDSA_ANY);
        psa_key_id_t stored = PSA_KEY_ID_NULL;
        status = psa_copy_key(transient.id(), &persistent, &stored);
        if (status == PSA_SUCCESS) {
            return make_key_reference(*id);
        } else if (status != PSA_ERROR_ALREADY_EXISTS) {
            return make_psa_error(status, SecurityModuleError::ModuleFailure);
        }
    }
    return make_psa_error(PSA_ERROR_ALREADY_EXISTS, SecurityModuleError::ModuleFailure);
}

expected<KeyReference> PsaSecurityModule::find_signing_key(const PublicKey& public_key)
{
    const std::string name = canonical_hexstring(public_key);
    if (name.empty()) {
        return make_error_code(SecurityModuleError::KeyNotFound);
    }

    const std::error_code error = psa::initialization_error();
    if (error) {
        return error;
    }

    const expected<psa_key_id_t> id = derive_key_id(name);
    if (!id) {
        return id.error();
    }

    const expected<KeyType> type = signing_key_type(*id, SecurityModuleError::KeyNotFound);
    if (!type) {
        return type.error();
    } else if (*type != public_key.type) {
        return make_error_code(SecurityModuleError::KeyNotFound);
    }

    // a foreign key may occupy the identifier
    const expected<PublicKey> stored = export_public_key(*id, *type);
    if (!stored) {
        return stored.error();
    } else if (canonical_hexstring(*stored) != name) {
        return make_error_code(SecurityModuleError::KeyNotFound);
    }
    return make_key_reference(*id);
}

expected<PublicKey> PsaSecurityModule::public_key(const KeyReference& reference)
{
    const expected<psa_key_id_t> id = key_id(reference);
    if (!id) {
        return id.error();
    }

    const std::error_code error = psa::initialization_error();
    if (error) {
        return error;
    }

    const expected<KeyType> type = signing_key_type(*id, SecurityModuleError::InvalidKeyReference);
    if (!type) {
        return type.error();
    }
    return export_public_key(*id, *type);
}

expected<Signature> PsaSecurityModule::sign(const ByteBuffer& digest, const KeyReference& reference)
{
    const expected<psa_key_id_t> id = key_id(reference);
    if (!id) {
        return id.error();
    }

    const std::error_code error = psa::initialization_error();
    if (error) {
        return error;
    }

    const expected<KeyType> type = signing_key_type(*id, SecurityModuleError::InvalidKeyReference);
    if (!type) {
        return type.error();
    }

    // PSA encodes r and s with field length each
    const std::size_t length = key_length(*type);
    ByteBuffer encoded(2 * length);
    std::size_t encoded_length = 0;
    const psa_status_t status = psa_sign_hash(*id, PSA_ALG_ECDSA_ANY, digest.data(), digest.size(),
        encoded.data(), encoded.size(), &encoded_length);
    if (status != PSA_SUCCESS) {
        return make_psa_error(status, SecurityModuleError::ModuleFailure);
    } else if (encoded_length != encoded.size()) {
        return make_error_code(SecurityModuleError::ModuleFailure);
    }

    Signature signature;
    signature.type = *type;
    signature.r.assign(encoded.begin(), encoded.begin() + length);
    signature.s.assign(encoded.begin() + length, encoded.end());
    return signature;
}

bool PsaSecurityModule::discard_key(const KeyReference& reference)
{
    const expected<psa_key_id_t> id = key_id(reference);
    if (!id || psa::initialization_error()) {
        return false;
    }

    // keys of this module are stored with the identifier derived from their public key, foreign keys are kept
    const expected<KeyType> type = signing_key_type(*id, SecurityModuleError::InvalidKeyReference);
    if (!type) {
        return false;
    }
    const expected<PublicKey> public_key = export_public_key(*id, *type);
    if (!public_key) {
        return false;
    }
    const expected<psa_key_id_t> derived = derive_key_id(canonical_hexstring(*public_key));
    return derived && *derived == *id && psa_destroy_key(*id) == PSA_SUCCESS;
}

expected<Aes128Key> PsaSecurityModule::generate_aes_key()
{
    const std::error_code error = psa::initialization_error();
    if (error) {
        return error;
    }

    Aes128Key key;
    const psa_status_t status = psa_generate_random(key.octets.data(), key.octets.size());
    if (status != PSA_SUCCESS) {
        return make_psa_error(status, SecurityModuleError::ModuleFailure);
    }
    return key;
}

expected<HmacKey> PsaSecurityModule::generate_hmac_key()
{
    const std::error_code error = psa::initialization_error();
    if (error) {
        return error;
    }

    HmacKey key;
    const psa_status_t status = psa_generate_random(key.octets.data(), key.octets.size());
    if (status != PSA_SUCCESS) {
        return make_psa_error(status, SecurityModuleError::ModuleFailure);
    }
    return key;
}

expected<EncryptedSymmetricKey> PsaSecurityModule::encrypt_key(
    const PublicKey& recipient, const Aes128Key& key, const Sha256Hash& info)
{
    const psa_ecc_family_t family = psa::ecc_family(recipient.type);
    if (family == 0) {
        return make_error_code(SecurityModuleError::UnsupportedKeyType);
    }

    const std::error_code error = psa::initialization_error();
    if (error) {
        return error;
    }

    const expected<ByteBuffer> recipient_point = psa::encode_uncompressed_point(recipient);
    if (!recipient_point) {
        return recipient_point.error();
    }

    psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
    psa_set_key_type(&attributes, PSA_KEY_TYPE_ECC_KEY_PAIR(family));
    psa_set_key_bits(&attributes, 8 * key_length(recipient.type));
    psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_DERIVE);
    psa_set_key_algorithm(&attributes, PSA_ALG_ECDH);
    psa::Key ephemeral;
    psa_status_t status = psa_generate_key(&attributes, ephemeral.output());
    if (status == PSA_ERROR_NOT_SUPPORTED) {
        return make_psa_error(status, SecurityModuleError::UnsupportedKeyType);
    } else if (status != PSA_SUCCESS) {
        return make_psa_error(status, SecurityModuleError::ModuleFailure);
    }

    ByteBuffer shared_secret(key_length(recipient.type));
    ScopedWipe wipe_shared_secret(shared_secret);
    std::size_t secret_length = 0;
    status = psa_raw_key_agreement(PSA_ALG_ECDH, ephemeral.id(), recipient_point->data(), recipient_point->size(),
        shared_secret.data(), shared_secret.size(), &secret_length);
    if (status == PSA_ERROR_INVALID_ARGUMENT) {
        return make_psa_error(status, SecurityModuleError::InvalidPublicKey);
    } else if (status != PSA_SUCCESS) {
        return make_psa_error(status, SecurityModuleError::ModuleFailure);
    } else if (secret_length != shared_secret.size()) {
        return make_error_code(SecurityModuleError::ModuleFailure);
    }

    const expected<PublicKey> ephemeral_key = export_public_key(ephemeral.id(), recipient.type);
    if (!ephemeral_key) {
        return ephemeral_key.error();
    }

    // this module derives keys and tag by PSA like an HSM does internally
    PsaCryptoProvider crypto;
    return security::encrypt_key(crypto, *ephemeral_key, create_byte_view(shared_secret), key, info);
}

} // namespace security
} // namespace vanetza
