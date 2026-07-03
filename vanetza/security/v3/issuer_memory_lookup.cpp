#include <vanetza/security/v3/issuer_memory_lookup.hpp>

namespace vanetza
{
namespace security
{
namespace v3
{

bool IssuerMemoryLookup::insert(const Certificate& cert)
{
    if (!cert.is_ca_certificate()) {
        return false;
    }
    auto digest = cert.calculate_digest();
    if (!digest) {
        return false;
    }
    auto it = m_certificates.find(*digest);
    if (it != m_certificates.end()) {
        it->second = cert;
    } else {
        m_certificates.emplace(*digest, cert);
    }
    return true;
}

const Certificate* IssuerMemoryLookup::find_issuer(const HashedId8& digest) const
{
    auto it = m_certificates.find(digest);
    return it == m_certificates.end() ? nullptr : &it->second;
}

} // namespace v3
} // namespace security
} // namespace vanetza
