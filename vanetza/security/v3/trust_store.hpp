#pragma once
#include <vanetza/security/hashed_id.hpp>
#include <vanetza/security/v3/certificate.hpp>
#include <list>
#include <map>

namespace vanetza
{
namespace security
{
namespace v3
{

class TrustStore
{
public:
    /**
     * Lookup certificates based on the passed HashedId8.
     *
     * \param id hash identifier of the certificate
     * \return all stored certificates matching the passed identifier
     */
    std::list<Certificate> lookup(HashedId8 id) const;

    /**
     * Insert a certificate into store, i.e. consider it as trustworthy.
     * \param trusted_certificate a trustworthy certificate copied into TrustStore
     */
    void insert(const Certificate& trusted_certificate);

protected:
    std::multimap<HashedId8, Certificate> m_certificates;
};

} // namespace v3
} // namespace security
} // namespace vanetza
