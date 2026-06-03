#pragma once

#include "credential_storage.hpp"
#include <vanetza/security/public_key.hpp>
#include <boost/range/adaptor/map.hpp>
#include <map>

namespace vanetza
{
namespace pki
{

// In-memory credential storage suitable for unit tests. Store/fetch/discard
// behave like a small std::map keyed by the public key's canonical hex string.
class MockCredentialStorage : public CredentialStorage
{
public:
    void store(const PublicKey& pub, const PrivateKey& priv) override
    {
        m_credentials[security::canonical_hexstring(pub)] = priv;
    }

    boost::optional<PrivateKey> fetch(const PublicKey& pub) override
    {
        auto it = m_credentials.find(security::canonical_hexstring(pub));
        if (it != m_credentials.end()) {
            return it->second;
        }
        return boost::none;
    }

    bool discard(const PublicKey& pub) override
    {
        return m_credentials.erase(security::canonical_hexstring(pub)) > 0;
    }

    CredentialNameRange list() const override
    {
        return m_credentials | boost::adaptors::map_keys;
    }

    bool discard(const std::string& canonical_hex) override
    {
        return m_credentials.erase(canonical_hex) > 0;
    }

    bool contains(const std::string& canonical_hex) const override
    {
        return m_credentials.count(canonical_hex) > 0;
    }

private:
    std::map<std::string, PrivateKey> m_credentials;
};

} // namespace pki
} // namespace vanetza
