#include "pdu_conversion.hpp"
#include "serialization_buffer.hpp"
#include <cassert>

namespace vanetza
{
namespace convertible
{

typedef std::unique_ptr<vanetza::geonet::Pdu> PduPtr;

void byte_buffer_impl<PduPtr>::convert(ByteBuffer& dest) const
{
    assert(m_pdu);
    geonet::serialize_into_buffer(*m_pdu, dest);
}

std::size_t byte_buffer_impl<PduPtr>::size() const
{
    assert(m_pdu);
    return m_pdu->length();
}

} // namespace convertible
} // namespace vanetza

