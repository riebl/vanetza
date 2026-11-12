#include <vanetza/security/memory_credential_storage.hpp>
#include <stdexcept>
#include <utility>

namespace vanetza
{
namespace security
{

void MemoryCredentialStorage::store(const PublicKey& pub, const PrivateKey& priv)
{
    std::string name = canonical_hexstring(pub);
    if (name.empty()) {
        // malformed public keys would share the empty name
        return;
    }

    ++m_modifications;
    m_credentials[std::move(name)] = priv;
}

boost::optional<PrivateKey> MemoryCredentialStorage::fetch(const PublicKey& pub)
{
    auto it = m_credentials.find(canonical_hexstring(pub));
    if (it != m_credentials.end()) {
        return it->second;
    }
    return boost::none;
}

bool MemoryCredentialStorage::discard(const PublicKey& pub)
{
    ++m_modifications;
    return m_credentials.erase(canonical_hexstring(pub)) > 0;
}

std::error_code MemoryCredentialStorage::visit(CredentialVisitor& visitor) const
{
    const unsigned modifications = m_modifications;
    for (const auto& credential : m_credentials) {
        visitor.visit(credential.first);
        if (m_modifications != modifications) {
            throw std::logic_error("credential storage modified while visiting");
        }
    }
    return std::error_code();
}

expected<bool> MemoryCredentialStorage::discard(const std::string& canonical_hex)
{
    ++m_modifications;
    return m_credentials.erase(canonical_hex) > 0;
}

expected<bool> MemoryCredentialStorage::contains(const std::string& canonical_hex) const
{
    return m_credentials.count(canonical_hex) > 0;
}

} // namespace security
} // namespace vanetza
