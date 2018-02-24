#ifndef VANETZA_CERTIFICATE_CACHE_HPP
#define VANETZA_CERTIFICATE_CACHE_HPP

#include <vanetza/common/clock.hpp>
#include <vanetza/common/runtime.hpp>
#include <vanetza/security/certificate.hpp>
#include <boost/heap/binomial_heap.hpp>
#include <list>
#include <map>

namespace vanetza
{
namespace security
{


/**
 * CertificateCache remembers validated certificates for some time.
 * This is necessary for certificate lookup when only its digest is known.
 */
class CertificateCache
{
public:
    CertificateCache(const Runtime& rt);

    /**
     * Puts a (validated) certificate into the cache.
     *
     * \param certificate certificate to add to the cache
     */
    void insert(const Certificate& certificate);

    /**
     * Lookup certificates based on the passed HashedId8.
     *
     * \param id hash identifier of the certificate
     * \param type type of certificate to lookup
     * \return all stored certificates matching the passed identifier and type
     */
    std::list<Certificate> lookup(const HashedId8& id, SubjectType type);

    /**
     * Number of currently stored certificates
     * \return cache size
     */
    std::size_t size() const { return m_certificates.size(); }

private:
    struct CachedCertificate;
    using map_type = std::multimap<HashedId8, CachedCertificate>;

    struct Expiry : public Clock::time_point
    {
        Expiry(Clock::time_point, map_type::iterator);
        const map_type::iterator certificate;
    };

    using heap_type = boost::heap::binomial_heap<Expiry, boost::heap::compare<std::greater<Expiry>>>;

    struct CachedCertificate
    {
        Certificate certificate;
        heap_type::handle_type handle;
    };

    const Runtime& m_runtime;
    heap_type m_expiries;
    map_type m_certificates;

    void drop_expired();
    bool is_expired(const Expiry&) const;
    void refresh(heap_type::handle_type&, Clock::duration);
};

} // namespace security
} // namespace vanetza

#endif /* VANETZA_CERTIFICATE_CACHE_HPP */
