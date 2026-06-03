#pragma once

#include "certificate_revocation_list.hpp"
#include "certificate_trust_list.hpp"
#include "hashed_id8.hpp"
#include "http.hpp"
#include <boost/optional/optional.hpp>
#include <string>

namespace vanetza
{
namespace pki
{

class DistributionCentre
{
public:
    DistributionCentre();

    void set_url(const std::string&);

    // TS 102 941 v1.4.1 Annex D.1.
    boost::optional<CertificateTrustList> fetch_trust_list(const HashedId8&);

    // TS 102 941 v1.4.1 Annex D.2.
    boost::optional<CertificateRevocationList> fetch_revocation_list(const HashedId8&);

private:
    HttpQuery m_base_query;
};

} // namespace pki
} // namespace vanetza
