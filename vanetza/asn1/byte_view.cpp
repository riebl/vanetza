#include <vanetza/asn1/asn1c_error.hpp>
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

void assign(OCTET_STRING_t& octets, const byte_view_range& bytes)
{
    if (OCTET_STRING_fromBuf(&octets, reinterpret_cast<const char*>(bytes.data()), bytes.size()) != 0) {
        throw asn1c_exception(asn1c_error(ErrorCode::OutOfMemory));
    }
}

void assign(OCTET_STRING_t& octets, const ByteBuffer& bytes)
{
    assign(octets, vanetza::create_byte_view(bytes));
}

} // namespace asn1
} // namespace vanetza
