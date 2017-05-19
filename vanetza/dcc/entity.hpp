#ifndef ENTITY_HPP_KUAWS3PK
#define ENTITY_HPP_KUAWS3PK

#include <vanetza/dcc/channel_probe_processor.hpp>
#include <vanetza/dcc/transmit_rate_control.hpp>

namespace vanetza
{
namespace dcc
{

class Entity
{
public:
    /**
     * Provide TRC interface for Facilities
     *
     * Cooperative Awareness adapts its message rate according to TRC (T_GenCam_Dcc).
     * \see EN 302 637-2 V1.3.2 (section 6.1.3)
     */
    virtual TransmitRateControl& transmit_rate_control() = 0;

    /**
     * Provide interface for reporting channel probes.
     *
     * Usually, radio hardware will generate these reports periodically.
     */
    virtual ChannelProbeProcessor& channel_probe_processor() = 0;

    virtual ~Entity() = default;
};

} // namespace dcc
} // namespace vanetza

#endif /* ENTITY_HPP_KUAWS3PK */

