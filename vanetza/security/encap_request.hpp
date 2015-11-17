#ifndef ENCAP_REQUEST_HPP
#define ENCAP_REQUEST_HPP

#include <boost/optional.hpp>
#include <vanetza/common/byte_buffer.hpp>
#include <vanetza/geonet/extended_pdu.hpp>
#include <vanetza/geonet/header_variant.hpp>
#include <vanetza/security/profile.hpp>

namespace vanetza
{
namespace security
{

/**
*   described in
*   TS 102 636-4-1 v1.2.3 (2015-01)
*/
struct EncapRequest {
    ByteBuffer plaintext_pdu;
    ByteBuffer plaintext_payload; // mandatory
    boost::optional<Profile> security_profile; // optional
};

} // namespace security
} // namespace vanetza

#endif // ENCAP_REQUEST_HPP
