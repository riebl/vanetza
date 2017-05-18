#ifndef CHANNEL_LOAD_SMOOTHING_HPP_TIJ4W5U3
#define CHANNEL_LOAD_SMOOTHING_HPP_TIJ4W5U3

#include <vanetza/dcc/channel_load.hpp>
#include <vanetza/dcc/channel_load.hpp>

namespace vanetza
{
namespace dcc
{

/**
 * Channel Load Smoothing component as per
 * C2C-CC Whitepaper on DCC for Day One (Version 1.0 from 2013)
 */
class ChannelLoadSmoothing
{
public:
    /**
     * Initializes smoothing as requested by Basic System Profile,
     * i.e. alpha = beta = 0.5
     */
    ChannelLoadSmoothing();

    /**
     * Initialize smoothing with custom smoothing factor
     * \param alpha value between 0.0 and 1.0
     */
    ChannelLoadSmoothing(ChannelLoad alpha);

    /**
     * Feed new channel load measurement into smoothing component
     * \param now current raw channel load measurement
     */
    void update(ChannelLoad now);

    ChannelLoad channel_load() const { return m_smoothed; }

private:
    const ChannelLoad m_alpha;
    ChannelLoad m_smoothed;
};

} // namespace dcc
} // namespace vanetza

#endif /* CHANNEL_LOAD_SMOOTHING_HPP_TIJ4W5U3 */

