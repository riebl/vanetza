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
    ByteBuffer sec_pdu; // mandatory
    SecuredMessage sec_packet;
};

} // namespace security
} // namespace vanetza
#endif // DECAP_REQUEST_HPP
