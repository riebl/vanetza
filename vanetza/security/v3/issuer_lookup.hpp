#pragma once
#include <vanetza/security/hashed_id.hpp>

namespace vanetza
{
namespace security
{
namespace v3
{

class Certificate;

/**
 * Resolves a signing certificate's issuer by digest, typically backed by
 * PKI-managed trust material rather than the peer-AT CertificateCache.
 */
class IssuerLookup
{
public:
    virtual ~IssuerLookup() = default;

    /**
     * \param digest issuer's HashedId8
     * \return pointer to the issuer certificate, or nullptr if unknown.
     */
    virtual const Certificate* find_issuer(const HashedId8& digest) const = 0;
};

} // namespace v3
} // namespace security
} // namespace vanetza
