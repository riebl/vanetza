#ifndef ENCAP_REQUEST_HPP_OX8CLPLW
#define ENCAP_REQUEST_HPP_OX8CLPLW

#include <vanetza/common/its_aid.hpp>
#include <vanetza/net/packet.hpp>

namespace vanetza
{
namespace security
{

/**
 * Input data for encapsulating a packet in a secured message
 * \see TS 102 723-8 for SN-ENCAP.request
 */
struct EncapRequest {
    DownPacket plaintext_payload; // mandatory
    ItsAid its_aid; // mandatory
};

} // namespace security
} // namespace vanetza

#endif // ENCAP_REQUEST_HPP_OX8CLPLW
