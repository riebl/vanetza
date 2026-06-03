#pragma once

#include "hashed_id8.hpp"
#include <vanetza/security/hashed_id.hpp>
#include <vanetza/security/v3/revocation_lookup.hpp>
#include <boost/optional/optional.hpp>
#include <filesystem>
#include <memory>
#include <unordered_map>
#include <unordered_set>

namespace vanetza
{
namespace pki
{

class CertificateRevocationList;
class SecurityModule;

/**
 * Constructor scans \p root and indexes every "*.crl" file.
 * store() replaces any prior CRL from the same issuer (one file per issuer).
 */
class CrlFilesystemStore : public security::v3::RevocationLookup
{
public:
    CrlFilesystemStore(std::shared_ptr<SecurityModule>, const std::filesystem::path& root);

    // Returns false if the CRL has no extractable issuer or a malformed payload.
    bool store(const CertificateRevocationList&);

    bool is_revoked(const security::HashedId8& issuer, const security::HashedId8& cert) const override;

protected:
    std::filesystem::path filename(const HashedId8&) const;
    boost::optional<HashedId8> index(const CertificateRevocationList&);

private:
    std::shared_ptr<SecurityModule> m_security;
    std::filesystem::path m_root;
    std::unordered_map<security::HashedId8, std::unordered_set<security::HashedId8>> m_revoked;
};

} // namespace pki
} // namespace vanetza
