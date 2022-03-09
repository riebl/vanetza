#include <vanetza/security/trust_store.hpp>

namespace vanetza
{
namespace security
{

void TrustStore::insert(const CertificateVariant& certificate)
{
    struct canonical_visitor : public boost::static_visitor<void>
    {
        void operator()(const Certificate& cert) const
        {
            if (cert.subject_info.subject_type != SubjectType::Root_CA) {
                throw std::runtime_error("Only root certificate authorities may be added to the trust store");
            }
        }
        void operator()(const CertificateV3& cert) const {}
    };
    boost::apply_visitor(canonical_visitor(), certificate);

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
