#include <vanetza/security/v3/revocation_lookup.hpp>

namespace vanetza
{
namespace security
{
namespace v3
{

void RevocationMemoryLookup::revoke(const HashedId8& issuer, const HashedId8& cert)
{
    m_revoked[issuer].insert(cert);
}

void RevocationMemoryLookup::clear(const HashedId8& issuer)
{
    m_revoked.erase(issuer);
}

bool RevocationMemoryLookup::is_revoked(const HashedId8& issuer, const HashedId8& cert) const
{
    auto it = m_revoked.find(issuer);
    if (it == m_revoked.end()) {
        return false;
    }
    return it->second.count(cert) != 0;
}

} // namespace v3
} // namespace security
} // namespace vanetza
