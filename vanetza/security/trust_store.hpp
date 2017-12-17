#ifndef VANETZA_TRUST_STORE_HPP
#define VANETZA_TRUST_STORE_HPP

#include <list>
#include <map>
#include <vanetza/security/certificate.hpp>
#include <vector>

namespace vanetza
{
namespace security
{

class TrustStore
{
public:
    /**
     * Create trust store with given trusted certificates
     * \param trusted_certificates these certificates are copied into trust store
     */
    TrustStore(const std::vector<Certificate>& trusted_certificates);

    /**
     * Lookup certificates based on the passed HashedId8.
     *
     * \param id hash identifier of the certificate
     * \return all stored certificates matching the passed identifier
     */
    std::list<Certificate> lookup(HashedId8 id) const;

private:
    std::multimap<HashedId8, Certificate> certificates;
};

} // namespace security
} // namespace vanetza

#endif /* VANETZA_TRUST_STORE_HPP */
