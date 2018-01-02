#ifndef VANETZA_TRUST_STORE_HPP
#define VANETZA_TRUST_STORE_HPP

#include <vanetza/security/certificate.hpp>
#include <list>
#include <map>

namespace vanetza
{
namespace security
{

class TrustStore
{
public:
    TrustStore() = default;

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

private:
    std::multimap<HashedId8, Certificate> m_certificates;
};

} // namespace security
} // namespace vanetza

#endif /* VANETZA_TRUST_STORE_HPP */
