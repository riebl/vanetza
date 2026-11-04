#include <vanetza/asn1/byte_view.hpp>
#include <vanetza/asn1/support/OCTET_STRING.h>

namespace vanetza
{
namespace asn1
{

byte_view_range create_byte_view(const OCTET_STRING_t& octets)
{
    return byte_view_range { byte_view_iterator(octets.buf), byte_view_iterator(octets.buf + octets.size) };
}

} // namespace asn1
} // namespace vanetza
