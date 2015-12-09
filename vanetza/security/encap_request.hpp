#ifndef ENCAP_REQUEST_HPP_OX8CLPLW
#define ENCAP_REQUEST_HPP_OX8CLPLW

#include <boost/optional.hpp>
#include <vanetza/common/byte_buffer.hpp>
#include <vanetza/geonet/extended_pdu.hpp>
#include <vanetza/geonet/header_variant.hpp>
#include <vanetza/security/profile.hpp>

namespace vanetza
{
namespace security
{

/** \brief contains input for signing process
*   described in
*   TS 102 636-4-1 v1.2.3 (2015-01)
*/
struct EncapRequest {
    ByteBuffer plaintext_payload; // mandatory
    boost::optional<Profile> security_profile; // optional
};

} // namespace security
} // namespace vanetza

#endif // ENCAP_REQUEST_HPP_OX8CLPLW
