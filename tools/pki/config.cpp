#include "asn1.hpp"
#include "certificate_trust_list.hpp"
#include "hashed_id8.hpp"

namespace vanetza
{
namespace pki
{

boost::optional<std::string> lookup_dc_url(const std::filesystem::path& ectl_file, const HashedId8& root_ca)
{
    struct DcUrlFinder : CtlVisitor
    {
        const HashedId8& root_ca;
        boost::optional<std::string> url;

        explicit DcUrlFinder(const HashedId8& ca) : root_ca(ca)
        {
        }

        void add_distribution_centre(const Vanetza_Security_DcEntry_t& dc) override
        {
            if (url) {
                return;
            }
            for (int j = 0; j < dc.cert.list.count; ++j) {
                if (dc.cert.list.array[j] && equals(*dc.cert.list.array[j], root_ca)) {
                    url = to_string(dc.url);
                    return;
                }
            }
        }
    };

    try {
        CertificateTrustList ctl = CertificateTrustList::from_file(ectl_file);
        DcUrlFinder finder { root_ca };
        ctl.visit_tlm_ctl(finder);
        return finder.url;
    } catch (const std::exception&) {
        // ECTL missing or malformed: treat as "no DC URL available"
        return boost::none;
    }
}

} // namespace pki
} // namespace vanetza
