#include <vanetza/security/trust_store.hpp>

namespace vanetza
{
namespace security
{

void TrustStore::insert(const CertificateVariant& certificate)
{
    if (CertificateVariantVersion(certificate.which()) == CertificateVariantVersion::Two){
        Certificate& temp_cert = boost::get<Certificate&>(certificate);
        if (temp_cert.subject_info.subject_type != SubjectType::Root_CA) {
            throw std::runtime_error("Only root certificate authorities may be added to the trust store");
        }   
    }

    HashedId8 id = calculate_hash(certificate);
    m_certificates.insert(std::make_pair(id, certificate));
}

std::list<CertificateVariant> TrustStore::lookup(HashedId8 id) const
{
    using iterator = std::multimap<HashedId8, CertificateVariant>::const_iterator;
    std::pair<iterator, iterator> range = m_certificates.equal_range(id);

    std::list<CertificateVariant> matches;
    for (auto item = range.first; item != range.second; ++item) {
        matches.push_back(item->second);
    }
    return matches;
}

} // namespace security
} // namespace vanetza
