#pragma once

#include <vanetza/security/credential_storage.hpp>
#include <vanetza/security/public_key.hpp>
#include <map>
#include <stdexcept>

namespace vanetza
{
namespace security
{

// In-memory credential storage suitable for unit tests. Store/fetch/discard
// behave like a small std::map keyed by the public key's canonical hex string.
// Modifications while visiting throw std::logic_error, see CredentialStorage::visit.
class MockCredentialStorage : public CredentialStorage
{
public:
    void store(const PublicKey& pub, const PrivateKey& priv) override
    {
        ++m_modifications;
        m_credentials[canonical_hexstring(pub)] = priv;
    }

    boost::optional<PrivateKey> fetch(const PublicKey& pub) override
    {
        auto it = m_credentials.find(canonical_hexstring(pub));
        if (it != m_credentials.end()) {
            return it->second;
        }
        return boost::none;
    }

    bool discard(const PublicKey& pub) override
    {
        ++m_modifications;
        return m_credentials.erase(canonical_hexstring(pub)) > 0;
    }

    std::error_code visit(CredentialVisitor& visitor) const override
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

    expected<bool> discard(const std::string& canonical_hex) override
    {
        ++m_modifications;
        return m_credentials.erase(canonical_hex) > 0;
    }

    expected<bool> contains(const std::string& canonical_hex) const override
    {
        return m_credentials.count(canonical_hex) > 0;
    }

private:
    std::map<std::string, PrivateKey> m_credentials;
    unsigned m_modifications = 0;
};

} // namespace security
} // namespace vanetza
