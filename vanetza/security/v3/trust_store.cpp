#include <vanetza/security/v3/trust_store.hpp>
#include <boost/optional.hpp>
#include <stdexcept>

namespace vanetza
{
namespace security
{
namespace v3
{

void TrustStore::insert(const Certificate& certificate)
{
    if (!certificate.issuer_is_self()) {
        throw std::runtime_error("Only root certificate authorities may be added to the trust store");
    }

    auto id = certificate.calculate_digest();
    if (!id) {
        throw std::runtime_error("Cannot calculate hash for certificate");
    }
    m_certificates.insert(std::make_pair(*id, certificate));
}

std::list<Certificate> TrustStore::lookup(HashedId8 id) const
{
    using iterator = std::multimap<HashedId8, Certificate>::const_iterator;
    std::pair<iterator, iterator> range = m_certificates.equal_range(id);

    std::list<Certificate> matches;
    for (auto item = range.first; item != range.second; ++item) {
        matches.push_back(item->second);
    }
    return matches;
}

} // namespace v3
} // namespace security
} // namespace vanetza
