#include "sequence_number.hpp"

namespace vanetza
{
namespace geonet
{

bool SequenceNumber::operator<(SequenceNumber other) const
{
    return ((other.m_number > m_number && other.m_number - m_number <= SequenceNumber::max/2) ||
        (m_number > other.m_number && m_number - other.m_number > SequenceNumber::max/2));
}

SequenceNumber SequenceNumber::operator++(int)
{
    SequenceNumber tmp = *this;
    ++m_number;
    return tmp;
}

void serialize(const SequenceNumber& sn, OutputArchive& ar)
{
    serialize(host_cast(static_cast<uint16_t>(sn)), ar);
}

void deserialize(SequenceNumber& sn, InputArchive& ar)
{
    uint16_t tmp = 0;
    deserialize(tmp, ar);
    sn = SequenceNumber(ntoh(tmp));
}

} // namespace geonet
} // namespace vanetza

