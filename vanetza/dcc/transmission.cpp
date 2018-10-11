#include "transmission.hpp"
#include <chrono>

namespace vanetza
{
namespace dcc
{

Clock::duration Transmission::channel_occupancy() const
{
    using namespace std::chrono;

    // assume 6 Mbps as default data rate
    const access::DataRateG5* rate = data_rate() ? data_rate() : &access::G5_6Mbps;

    // PHY
    static const auto phy_preamble = microseconds(32);
    static const auto phy_signal = microseconds(8);

    // MAC
    static const std::size_t bytes_epd = 2; // EtherType Protocol Discrimination (no LLC!)
    static const std::size_t bytes_mac = 34; // 802.11 MAC header

    const std::size_t bytes = rate->data_length(body_length() + bytes_epd + bytes_mac);
    const double seconds_per_byte = 1.0 / (rate->bytes_per_second());
    const duration<double> data_duration { bytes * seconds_per_byte };

    return phy_preamble + phy_signal + duration_cast<microseconds>(data_duration);
}


} // namespace dcc
} // namespace vanetza
