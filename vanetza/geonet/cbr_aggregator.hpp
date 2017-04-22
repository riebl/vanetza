#ifndef CBR_AGGREGATOR_HPP_VUGJW6BW
#define CBR_AGGREGATOR_HPP_VUGJW6BW

#include <vanetza/dcc/channel_load.hpp>
#include <vanetza/geonet/timestamp.hpp>
#include <array>

namespace vanetza
{
namespace geonet
{

class LocationTable;


/**
 * CbrAggregator realises the CBR aggregration as specified by TS 102 636-4-2 V1.1.1, section 5.2.2
 *
 * Since this algorithm relies mainly on location table entries it is placed in the geonet module.
 */
class CbrAggregator
{
public:
    using ChannelLoad = dcc::ChannelLoad;

    CbrAggregator();

    /**
     * Get local channel busy ratio, i.e. CBR_L_0_Hop
     * \return CBR
     */
    ChannelLoad get_local_cbr() const { return m_local_cbr[0]; }

    /**
     * Get one-hop channel busy ratio, i.e. CBR_L_1_Hop
     * \return CBR
     */
    ChannelLoad get_one_hop_cbr() const { return m_one_hop_cbr; }

    /**
     * Get two-hop channel busy ratio, i.e. CBR_L_2_Hop
     * \return CBR
     */
    ChannelLoad get_two_hop_cbr() const { return m_two_hop_cbr; }

    /**
     * Get global channel busy ratio
     * \return CBR
     */
    ChannelLoad get_global_cbr() const { return m_global_cbr; }

    /**
     * Aggregate {1,2}-hop CBRs from received CBR values stored in location table
     * \parame local most recent local CBR measurement CBR_L_0_Hop
     * \param lt location table containing LocTEX_G5 entries
     * \param cbr_lifetime reject entries older than T_cbr
     * \param cbr_target reference value
     */
    void aggregate(ChannelLoad cbr_local, const LocationTable& lt, Timestamp cbr_lifetime, ChannelLoad cbr_target);

private:
    std::array<ChannelLoad, 2> m_local_cbr;
    ChannelLoad m_one_hop_cbr;
    ChannelLoad m_two_hop_cbr;
    ChannelLoad m_global_cbr;
};

} // namespace geonet
} // namespace vanetza

#endif /* CBR_AGGREGATOR_HPP_VUGJW6BW */

