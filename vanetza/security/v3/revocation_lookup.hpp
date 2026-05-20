#pragma once
#include <vanetza/security/hashed_id.hpp>
#include <unordered_map>
#include <unordered_set>

namespace vanetza
{
namespace security
{
namespace v3
{

/**
 * Lookup for HashedId8-style certificate revocation.
 *
 * Backs the chain-walk performed by DefaultCertificateValidator: for every
 * non-root certificate the validator encounters while walking up the chain,
 * it asks whether that certificate has been revoked by a CRL signed by its
 * issuer.
 *
 * Linkage-value CRLs (TS 102 941 ToBeSignedLinkageValueCrl) are out of scope:
 * the European C-ITS Certificate Policy does not revoke ATs, and revoking CAs
 * only ever needs HashedId8 entries.
 */
class RevocationLookup
{
public:
    virtual ~RevocationLookup() = default;

    /**
     * \param issuer HashedId8 of the CA whose CRL is consulted
     * \param cert   HashedId8 of the certificate being checked
     * \return true iff the CRL signed by \p issuer lists \p cert as revoked
     */
    virtual bool is_revoked(const HashedId8& issuer, const HashedId8& cert) const = 0;
};

/**
 * In-memory RevocationLookup, indexed by issuer HashedId8.
 */
class RevocationMemoryLookup : public RevocationLookup
{
public:
    void revoke(const HashedId8& issuer, const HashedId8& cert);
    void clear(const HashedId8& issuer);

    bool is_revoked(const HashedId8& issuer, const HashedId8& cert) const override;

private:
    std::unordered_map<HashedId8, std::unordered_set<HashedId8>> m_revoked;
};

} // namespace v3
} // namespace security
} // namespace vanetza
