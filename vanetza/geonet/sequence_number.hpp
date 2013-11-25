#ifndef SEQUENCE_NUMBER_HPP_HEO4A3XC
#define SEQUENCE_NUMBER_HPP_HEO4A3XC

#include <boost/operators.hpp>
#include <cstdint>
#include <limits>

namespace vanetza
{
namespace geonet
{

class SequenceNumber :
    public boost::totally_ordered<SequenceNumber>,
    public boost::additive<SequenceNumber>
{
public:
    static const uint16_t max = std::numeric_limits<uint16_t>::max();

    SequenceNumber() : m_number(0) {}
    explicit SequenceNumber(uint16_t number) : m_number(number) {}
    explicit operator uint16_t() const { return m_number; }
    bool operator<(SequenceNumber other) const { return m_number < other.m_number; }
    bool operator==(SequenceNumber other) const { return m_number == other.m_number; }
    void operator+=(SequenceNumber other) { m_number += other.m_number; }
    void operator-=(SequenceNumber other) { m_number -= other.m_number; }

private:
    uint16_t m_number;
};

} // namespace geonet
} // namespace vanetza

#endif /* SEQUENCE_NUMBER_HPP_HEO4A3XC */

