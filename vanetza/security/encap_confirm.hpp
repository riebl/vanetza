#ifndef ENCAP_CONFIRM_HPP
#define ENCAP_CONFIRM_HPP

#include <vanetza/geonet/extended_pdu.hpp>
#include <vanetza/common/byte_buffer.hpp>

namespace vanetza
{
namespace security
{

/**
* described in
* TS 102 636-4-1 v1.2.3 (2015-01)
*/
template<class HEADER>
struct EncapConfirm {
    geonet::ExtendedPdu<HEADER> sec_pdu; // mandatory
    ByteBuffer sec_payload; // sec_pdu and sec_payload forms the sec_packet, which is described by ETSI; mandatory
};

} // namespace security
} // namespace vanetza
#endif // ENCAP_CONFIRM_HPP
