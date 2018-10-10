#ifndef DATA_RATES_802DOT11P_HPP_SL3RZPZO
#define DATA_RATES_802DOT11P_HPP_SL3RZPZO

#include <cstddef>

namespace vanetza
{
namespace access
{

class DataRateG5
{
public:
    /**
     * Create data rate for ITS-G5 band
     * \param kbps kilo-bits per second transfer rate
     * \param cbits number of coded bits per symbol
     */
    constexpr DataRateG5(unsigned kbps, unsigned cbits) :
        m_bytes_per_second(kbps * 1000 / 8),
        m_coded_bits_per_symbol(cbits) {}

    /**
     * Get tranfer rate as number of bytes per second
     * \return transfer rate
     */
    unsigned bytes_per_second() const { return m_bytes_per_second; }

    /**
     * Calculate length of PHY data length
     * \param psdu size of PSDU, i.e. MPDU (MAC header + payload)
     * \return length in bytes
     */
    std::size_t data_length(std::size_t psdu) const;

private:
    unsigned m_bytes_per_second;
    unsigned m_coded_bits_per_symbol;
};

static const DataRateG5 G5_3Mbps { 3000, 48 };
static const DataRateG5 G5_4dot5Mbps { 4500, 48 };
static const DataRateG5 G5_6Mbps { 6000, 96 };
static const DataRateG5 G5_9Mbps { 9000, 96 };
static const DataRateG5 G5_12Mbps { 12000, 192 };
static const DataRateG5 G5_18bps { 18000, 192 };
static const DataRateG5 G5_24Mbps { 24000, 288 };
static const DataRateG5 G5_27Mbps { 27000, 288 };

} // namespace access
} // namespace vanetza

#endif /* DATA_RATES_802DOT11P_HPP_SL3RZPZO */

