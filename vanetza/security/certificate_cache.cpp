#include <vanetza/security/certificate_cache.hpp>
#include <chrono>

namespace vanetza
{
namespace security
{

CertificateCache::CertificateCache(const Runtime& rt) : m_runtime(rt)
{
}

void CertificateCache::insert(const Certificate& certificate)
{
    const HashedId8 id = calculate_hash(certificate);

    // this may drop expired entries and extend some's lifetime
    std::list<Certificate> certs = lookup(id, certificate.subject_info.subject_type);

    // TODO: implement equality comparison for Certificate
    if (certs.size()) {
        const auto binary_insert = convert_for_signing(certificate);
        for (auto& cert : certs) {
            const auto binary_found = convert_for_signing(cert);
            if (binary_insert == binary_found) {
                return;
            }
        }
    }

    Clock::duration lifetime = Clock::duration::zero();
    if (certificate.subject_info.subject_type == SubjectType::Authorization_Ticket) {
        // section 7.1 in ETSI TS 103 097 v1.2.1
        // there must be a CAM with the authorization ticket every one second
        // we choose two seconds here to account for one missed message
        lifetime = std::chrono::seconds(2);
    } else if (certificate.subject_info.subject_type == SubjectType::Authorization_Authority) {
        // section 7.1 in ETSI TS 103 097 v1.2.1
        // chains are only sent upon request, there will probably only be a few authoritation authorities in use
        // one hour is an arbitrarily choosen cache period for now
        lifetime = std::chrono::seconds(3600);
    }

    if (lifetime > Clock::duration::zero()) {
        CachedCertificate entry;
        entry.certificate = certificate;
        map_type::iterator stored = m_certificates.emplace(id, entry);
        heap_type::handle_type& handle = stored->second.handle;
        handle = m_expiries.push(Expiry { m_runtime.now() + lifetime, stored });
    }
}

std::list<Certificate> CertificateCache::lookup(const HashedId8& id, SubjectType type)
{
    drop_expired();

    using iterator = std::multimap<HashedId8, CachedCertificate>::iterator;
    std::pair<iterator, iterator> range = m_certificates.equal_range(id);

    std::list<Certificate> matches;
    for (auto item = range.first; item != range.second; ++item) {
        const Certificate& cert = item->second.certificate;

        auto subject_type = cert.subject_info.subject_type;
        if (subject_type != type) {
            continue;
        }

        matches.push_back(cert);

        // renew cached certificate
        if (subject_type == SubjectType::Authorization_Ticket) {
            refresh(item->second.handle, std::chrono::seconds(2));
        } else if (subject_type == SubjectType::Authorization_Authority) {
            refresh(item->second.handle, std::chrono::seconds(3600));
        }
    }

    return matches;
}

void CertificateCache::drop_expired()
{
    while (!m_expiries.empty() && is_expired(m_expiries.top())) {
        m_certificates.erase(m_expiries.top().certificate);
        m_expiries.pop();
    }
}

bool CertificateCache::is_expired(const Expiry& expiry) const
{
    return m_runtime.now() > expiry;
}

void CertificateCache::refresh(heap_type::handle_type& handle, Clock::duration lifetime)
{
    static_cast<Clock::time_point&>(*handle) = m_runtime.now() + lifetime;
    m_expiries.update(handle);
}

CertificateCache::Expiry::Expiry(Clock::time_point expiry, map_type::iterator it) :
    Clock::time_point(expiry), certificate(it)
{
}

} // namespace security
} // namespace vanetza
