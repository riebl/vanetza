#include <vanetza/security/trust_store.hpp>

namespace vanetza
{
namespace security
{

void TrustStore::insert(const Certificate& certificate)
{
    if (certificate.subject_info.subject_type != SubjectType::Root_CA) {
        throw std::runtime_error("Only root certificate authorities may be added to the trust store");
    }

    HashedId8 id = calculate_hash(certificate);
    m_certificates.insert(std::make_pair(id, certificate));
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

void TrustStoreV3::insert(const CertificateV3& certificate)
{
    // There is no way to know if the certificate is root
    // if (certificate.subject_info.subject_type != SubjectType::Root_CA) {
    //     throw std::runtime_error("Only root certificate authorities may be added to the trust store");
    // }

    HashedId8 id = certificate.calculate_hash();
    m_certificates.insert(std::make_pair(id, certificate));
}

std::list<CertificateV3> TrustStoreV3::lookup(HashedId8 id) const
{
    using iterator = std::multimap<HashedId8, CertificateV3>::const_iterator;
    std::pair<iterator, iterator> range = m_certificates.equal_range(id);

    std::list<CertificateV3> matches;
    for (auto item = range.first; item != range.second; ++item) {
        matches.push_back(item->second);
    }
    return matches;
}

} // namespace security
} // namespace vanetza
