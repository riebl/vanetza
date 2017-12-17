#include <vanetza/security/certificate_cache.hpp>

namespace vanetza
{
namespace security
{

CertificateCache::CertificateCache(const Clock::time_point& time_now): time_now(time_now) { }

void CertificateCache::put(Certificate certificate)
{
    evict_entries();

    HashedId8 id = calculate_hash(certificate);

    std::list<Certificate> certs = lookup(id);

    // TODO: This is probably horribly inefficient, find most efficient but still correct comparison
    if (certs.size()) {
        auto binary_cert = convert_for_signing(certificate);

        for (auto& cert : certs) {
            auto binary = convert_for_signing(cert);

            if (binary == binary_cert) {
                return;
            }
        }
    }

    CacheEntry entry;
    entry.certificate = certificate;

    if (certificate.subject_info.subject_type == SubjectType::Authorization_Ticket) {
        // section 7.1 in ETSI TS 103 097 v1.2.1
        // there must be a CAM with the authorization ticket every one second
        // we choose two seconds here to account for one missed message
        entry.evict_time = time_now + std::chrono::seconds(2);
    } else if (certificate.subject_info.subject_type == SubjectType::Authorization_Authority) {
        // section 7.1 in ETSI TS 103 097 v1.2.1
        // chains are only sent upon request, there will probably only be a few authoritation authorities in use
        // one hour is an arbitrarily choosen cache period for now
        entry.evict_time = time_now + std::chrono::seconds(3600);
    } else {
        // shouldn't happen, we ignore other certificates
        return;
    }

    certificates.insert(std::make_pair(id, entry));
}

std::list<Certificate> CertificateCache::lookup(HashedId8 id)
{
    using iterator = std::multimap<HashedId8, CacheEntry>::iterator;
    std::pair<iterator, iterator> range = certificates.equal_range(id);

    std::list<Certificate> matches;

    for (auto item = range.first; item != range.second; ++item) {
        matches.push_back(item->second.certificate);

        // renew cache entry, see CertificateCache::put()
        auto subject_type = item->second.certificate.subject_info.subject_type;

        if (subject_type == SubjectType::Authorization_Ticket) {
            item->second.evict_time = time_now + std::chrono::seconds(2);
        } else if (subject_type == SubjectType::Authorization_Authority) {
            item->second.evict_time = time_now + std::chrono::seconds(3600);
        }
    }

    // evict after lookup, so we don't evict items we need just now
    evict_entries();

    return matches;
}

void CertificateCache::evict_entries()
{
    // TODO: Optimize performance. Currently it scans all entries on each access.
    for (auto i = certificates.begin(); i != certificates.end();) {
        if (i->second.evict_time < time_now) {
            i = certificates.erase(i);
        } else {
            ++i;
        }
    }
}

} // namespace security
} // namespace vanetza
