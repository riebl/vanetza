#ifndef CHANNEL_LOAD_HPP_D1JOCNLP
#define CHANNEL_LOAD_HPP_D1JOCNLP

#include <vanetza/common/unit_interval.hpp>

namespace vanetza
{
namespace dcc
{

class ChannelLoad : public UnitInterval
{
public:
    using UnitInterval::UnitInterval;
    ChannelLoad() = default;
    ChannelLoad(const UnitInterval&);

    /**
     * Create ChannelLoad from rational probes
     * \see ChannelLoad::create_from_probes
     *
     * \param probes_busy number of probes above busy threshold
     * \param probes_total total number of probes
     */
    ChannelLoad(unsigned probes_busy, unsigned probes_total);

    /**
     * Calculate UnitInterval representing ChannelLoad from rational probes
     * \param probes_busy number of probes above busy threshold
     * \param probes_total total number of probes
     * \return interval representing channel load (capped if probes_total < probes_busy)
     */
    static UnitInterval create_from_probes(unsigned probes_busy, unsigned probes_total);
};

} // namespace dcc
} // namespace vanetza

#endif /* CHANNEL_LOAD_HPP_D1JOCNLP */

