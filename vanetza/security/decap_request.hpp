#ifndef DECAP_REQUEST_HPP
#define DECAP_REQUEST_HPP

#include <vanetza/geonet/parsed_pdu.hpp>
#include <vanetza/common/byte_buffer.hpp>

/**
* described in
* TS 102 723-8 v1.0.0 (2013-07)
* TS 102 636-4-1 v1.2.3 (2015-01)
*/

namespace vanetza
{
namespace security
{

struct DecapRequest
{
    // plaintext_packet_length is gathered via ByteBuffer::size(); valid range 0 ... 2^16-1; mandatory
    geonet::ParsedPdu sec_pdu; // mandatory
    ByteBuffer sec_payload; // sec_pdu and sec_payload forms the sec_packet, which is described by ETSI; mandatory
};

} // namespace security
} // namespace vanetza
#endif // DECAP_REQUEST_HPP
