#pragma once

#include <vanetza/security/credential_storage.hpp>
#include <map>
#include <string>

namespace vanetza
{
namespace security
{

/**
 * \brief Volatile credential storage keeping private keys in memory.
 *
 * All optional operations are supported. Visitors modifying this storage cause std::logic_error.
 */
class MemoryCredentialStorage : public CredentialStorage
{
public:
    /// \brief Store private key unless its public key is malformed.
    void store(const PublicKey&, const PrivateKey&) override;
    boost::optional<PrivateKey> fetch(const PublicKey&) override;
    bool discard(const PublicKey&) override;
    std::error_code visit(CredentialVisitor&) const override;
    expected<bool> discard(const std::string& canonical_hex) override;
    expected<bool> contains(const std::string& canonical_hex) const override;

private:
    std::map<std::string, PrivateKey> m_credentials;
    unsigned m_modifications = 0;
};

} // namespace security
} // namespace vanetza
