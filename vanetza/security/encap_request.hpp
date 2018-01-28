#ifndef ENCAP_REQUEST_HPP_OX8CLPLW
#define ENCAP_REQUEST_HPP_OX8CLPLW

#include <vanetza/net/packet.hpp>
#include <vanetza/security/int_x.hpp>
#include <boost/optional.hpp>

namespace vanetza
{
namespace security
{

/** \brief contains input for signing process
 *  described in TS 102 636-4-1 v1.2.3 (2015-01)
 *  uses ITS application IDs instead of security profile
 */
struct EncapRequest {
    DownPacket plaintext_payload; // mandatory
    IntX its_aid; // optional
};

} // namespace security
} // namespace vanetza

#endif // ENCAP_REQUEST_HPP_OX8CLPLW
