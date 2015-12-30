#include <vanetza/geonet/basic_header.hpp>
#include <vanetza/geonet/common_header.hpp>
#include <vanetza/geonet/header_variant.hpp>
#include <vanetza/geonet/pdu.hpp>
#include <vanetza/security/secured_message.hpp>

namespace vanetza
{
namespace geonet
{

void serialize(const Pdu& pdu, OutputArchive& ar)
{
    serialize(pdu.basic(), ar);
    if (pdu.secured()) {
        security::serialize(ar, *pdu.secured());
    } else {
        geonet::serialize(pdu.common(), ar);
        boost::serialize(pdu.extended_variant(), ar);
    }
}

} // namespace geonet
} // namespace vanetza
