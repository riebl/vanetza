#ifndef SMOOTHING_CHANNEL_PROBE_PROCESSOR_HPP_EIP1WUDK
#define SMOOTHING_CHANNEL_PROBE_PROCESSOR_HPP_EIP1WUDK

#include <vanetza/common/unit_interval.hpp>
#include <vanetza/dcc/channel_load.hpp>
#include <vanetza/dcc/channel_probe_processor.hpp>
#include <functional>

namespace vanetza
{
namespace dcc
{

/**
 * Smooth local channel load measurements as per
 * C2C-CC Whitepaper on DCC for Day One (Version 1.0 from 2013)
 * and Basic System Profile (RS_BSP_240 in Version 1.3)
 */
class SmoothingChannelProbeProcessor : public ChannelProbeProcessor
{
public:
    using OnUpdateFn = std::function<void(ChannelLoad)>;

    /**
     * Initialize ChannelProbeProcessor with smoothing behaviour.
     * \param fn update function to be called when new smoothed channel load is available
     * \param alpha smoothing factor (influence of new raw measurement)
     */
    SmoothingChannelProbeProcessor(const OnUpdateFn& fn, UnitInterval alpha = UnitInterval(0.5));

    /**
     * Feed new local channel load measurement into smoothing algorithm.
     * Side effect: Update function is called afterwards with smoothed channel load.
     * \param cl raw local channel load
     */
    void indicate(ChannelLoad cl) override;

    /**
     * Get smoothed channel load value
     */
    ChannelLoad channel_load() const;

private:
    UnitInterval m_alpha;
    ChannelLoad m_channel_load;
    OnUpdateFn m_update_fn;
};

} // namespace dcc
} // namespace vanetza

#endif /* SMOOTH_CHANNEL_PROBE_PROCESSOR_HPP_EIP1WUDK */

