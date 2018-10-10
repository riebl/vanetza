#include "data_rates.hpp"
#include <cassert>

namespace vanetza
{
namespace access
{

std::size_t DataRateG5::data_length(std::size_t psdu) const
{
    static const unsigned service_bits = 16;
    static const unsigned tail_bits = 6;

    const unsigned body = service_bits + tail_bits + psdu * 8;
    unsigned padding = body % m_coded_bits_per_symbol;
    if (padding > 0) {
        padding = m_coded_bits_per_symbol - padding;
    }

    assert((body + padding) % 8 == 0);
    return (body + padding) / 8;
}

} // namespace access
} // namespace vanetza
