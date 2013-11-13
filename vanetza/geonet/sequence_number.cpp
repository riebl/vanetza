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

} // namespace geonet
} // namespace vanetza

