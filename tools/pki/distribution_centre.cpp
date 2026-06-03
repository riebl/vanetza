#include "distribution_centre.hpp"
#include "http.hpp"

namespace vanetza
{
namespace pki
{

DistributionCentre::DistributionCentre()
{
}

void DistributionCentre::set_url(const std::string& url)
{
    m_base_query = HttpQuery::from_url(url);
}

boost::optional<CertificateTrustList> DistributionCentre::fetch_trust_list(const HashedId8& digest)
{
    HttpQuery query = m_base_query;
    query.path += "/getctl/" + hexstring(digest);

    HttpResponse response = http_get(query);
    if (response.result() != boost::beast::http::status::ok) {
        return boost::none;
    } else if (response[boost::beast::http::field::content_type] != "application/x-its-ctl") {
        return boost::none;
    }

    CertificateTrustList trust_list;
    if (trust_list.decode(response.body())) {
        return trust_list;
    } else {
        return boost::none;
    }
}

boost::optional<CertificateRevocationList> DistributionCentre::fetch_revocation_list(const HashedId8& digest)
{
    // TS 102 941 v1.4.1 Annex D.2: GET <dc>/getcrl/<UPPERCASE-HEX-HashedId8>; reply application/x-its-crl.
    HttpQuery query = m_base_query;
    query.path += "/getcrl/" + hexstring(digest);

    HttpResponse response = http_get(query);
    if (response.result() != boost::beast::http::status::ok) {
        return boost::none;
    } else if (response[boost::beast::http::field::content_type] != "application/x-its-crl") {
        return boost::none;
    }

    CertificateRevocationList crl;
    if (crl.decode(response.body())) {
        return crl;
    } else {
        return boost::none;
    }
}

} // namespace pki
} // namespace vanetza
