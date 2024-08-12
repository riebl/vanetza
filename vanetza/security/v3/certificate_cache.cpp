#include <vanetza/security/v3/certificate_cache.hpp>
#include <boost/optional/optional.hpp>

namespace vanetza
{
namespace security
{
namespace v3
{

const Certificate* CertificateCache::lookup(const HashedId8& digest) const
{
    auto found = m_storage.find(digest);
    if (found != m_storage.end()) {
        return &found->second;
    } else {
        return nullptr;
    }
}

void CertificateCache::store(const Certificate& cert)
{
    auto maybe_hash = cert.calculate_digest();
    if (maybe_hash) {
        m_storage[*maybe_hash] = cert;
    }
}

} // namespace v3
} // namespace security
} // namespace vanetza
