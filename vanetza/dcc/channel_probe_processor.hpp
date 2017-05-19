#ifndef CHANNEL_PROBE_PROCESSOR_HPP_QBFTHSVC
#define CHANNEL_PROBE_PROCESSOR_HPP_QBFTHSVC

#include <vanetza/dcc/channel_load.hpp>

namespace vanetza
{
namespace dcc
{

/**
 * Access point for radio layers to propagate their local channel load measurements
 */
class ChannelProbeProcessor
{
public:
    /**
     * Indicate a new channel load measurement
     * \see TS 102 686 V1.1.1 Annex A.1.2 for definition of "channel load"
     *
     * \param cl locally measured channel load
     */
    virtual void indicate(ChannelLoad cl) = 0;

    virtual ~ChannelProbeProcessor() = default;
};

} // namespace dcc
} // namespace vanetza

#endif /* CHANNEL_PROBE_PROCESSOR_HPP_QBFTHSVC */

