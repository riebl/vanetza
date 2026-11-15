#include <vanetza/security/credential_storage.hpp>
#include <vanetza/security/security_module_error.hpp>
#include <vanetza/security/software_signing_keys.hpp>
#include <stdexcept>
#include <utility>

namespace vanetza
{
namespace security
{

namespace
{

expected<PrivateKey> parse_key_reference(const KeyReference& reference)
{
    const ByteBuffer& data = reference.data;
    const KeyType type = data.empty() ? KeyType::Unspecified : static_cast<KeyType>(data.front());
    const std::size_t length = key_length(type); // zero for unsupported key types
    if (length == 0 || data.size() != 1 + length) {
        return make_error_code(SecurityModuleError::InvalidKeyReference);
    }

    PrivateKey key;
    key.type = type;
    key.key.assign(data.begin() + 1, data.end());
    return key;
}

KeyReference make_key_reference(const PrivateKey& key)
{
    KeyReference reference;
    reference.data.reserve(1 + key.key.size());
    reference.data.push_back(static_cast<std::uint8_t>(key.type));
    reference.data.insert(reference.data.end(), key.key.begin(), key.key.end());
    return reference;
}

} // namespace

SoftwareSigningKeys::SoftwareSigningKeys(std::shared_ptr<CredentialStorage> storage) :
    m_credential_storage(std::move(storage))
{
}

expected<KeyReference> SoftwareSigningKeys::create_key(KeyType type)
{
    if (key_length(type) == 0) {
        return make_error_code(SecurityModuleError::UnsupportedKeyType);
    }

    expected<PrivateKey> priv_key = generate_private_key(type);
    if (!priv_key) {
        return priv_key.error();
    }

    expected<PublicKey> pub_key = derive_public_key(*priv_key);
    if (!pub_key) {
        return pub_key.error();
    }

    const std::error_code error = store_credential(*pub_key, *priv_key);
    if (error) {
        return error;
    }
    return make_key_reference(*priv_key);
}

expected<KeyReference> SoftwareSigningKeys::import_key(const PrivateKey& key)
{
    const std::size_t length = key_length(key.type); // zero for unsupported key types
    if (length == 0) {
        return make_error_code(SecurityModuleError::UnsupportedKeyType);
    } else if (key.key.size() != length) {
        return make_error_code(SecurityModuleError::InvalidPrivateKey);
    }

    expected<PublicKey> pub_key = derive_public_key(key);
    if (!pub_key) {
        // the hook reports a scalar out of range like an invalid key reference
        return pub_key.error() == SecurityModuleError::InvalidKeyReference ?
            make_error_code(SecurityModuleError::InvalidPrivateKey) : pub_key.error();
    }

    const std::error_code error = store_credential(*pub_key, key);
    if (error) {
        return error;
    }
    return make_key_reference(key);
}

std::error_code SoftwareSigningKeys::store_credential(const PublicKey& pub_key, const PrivateKey& priv_key)
{
    if (m_credential_storage) {
        try {
            m_credential_storage->store(pub_key, priv_key);
        } catch (const std::runtime_error&) {
            // credential storage reports failures by exceptions
            return make_error_code(SecurityModuleError::ModuleFailure);
        }
    }
    return {};
}

expected<KeyReference> SoftwareSigningKeys::find_key(const PublicKey& key)
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
    if (!public_key_of(reference)) {
        return make_error_code(SecurityModuleError::ModuleFailure);
    }
    return reference;
}

expected<PublicKey> SoftwareSigningKeys::public_key_of(const KeyReference& reference)
{
    expected<PrivateKey> priv_key = parse_key_reference(reference);
    if (!priv_key) {
        return priv_key.error();
    }
    return derive_public_key(*priv_key);
}

expected<Signature> SoftwareSigningKeys::sign_with(const ByteBuffer& digest, const KeyReference& reference)
{
    expected<PrivateKey> priv_key = parse_key_reference(reference);
    if (!priv_key) {
        return priv_key.error();
    }
    return sign_digest(digest, *priv_key);
}

bool SoftwareSigningKeys::discard(const KeyReference& reference)
{
    expected<PublicKey> pub_key = public_key_of(reference);
    // without credential storage there are no module resources to release
    return pub_key && (!m_credential_storage || m_credential_storage->discard(*pub_key));
}

} // namespace security
} // namespace vanetza
