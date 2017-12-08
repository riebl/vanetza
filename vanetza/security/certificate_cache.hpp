#ifndef VANETZA_CERTIFICATE_CACHE_HPP
#define VANETZA_CERTIFICATE_CACHE_HPP

#include <vanetza/common/clock.hpp>
#include <vanetza/security/certificate.hpp>
#include <list>
#include <map>

namespace vanetza
{
namespace security
{

class CertificateCache
{
public:
    CertificateCache(const Clock::time_point& time_now);

    /**
     * Puts a certificate into the cache.
     *
     * \param certificate certificate to add to the cache
     */
    void insert(const Certificate& certificate);

    /**
     * Lookup certificates based on the passed HashedId8.
     *
     * \param id hash identifier of the certificate
     * \return all stored certificates matching the passed identifier
     */
    std::list<Certificate> lookup(HashedId8 id);

private:
    struct CacheEntry
    {
        Certificate certificate;
        Clock::time_point evict_time;
    };

    const Clock::time_point& time_now;
    std::multimap<HashedId8, CacheEntry> certificates;

    void evict_entries();
};

} // namespace security
} // namespace vanetza

#endif /* VANETZA_CERTIFICATE_CACHE_HPP */
