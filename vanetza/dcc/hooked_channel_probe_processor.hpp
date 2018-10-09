#ifndef HOOKED_CHANNEL_PROBE_PROCESSOR_HPP_M1O7VHKS
#define HOOKED_CHANNEL_PROBE_PROCESSOR_HPP_M1O7VHKS

#include <vanetza/common/hook.hpp>
#include <vanetza/dcc/channel_probe_processor.hpp>

namespace vanetza
{
namespace dcc
{

/**
 * Implementation of ChannelProbeProcessor invoking hook on indication
 */
class HookedChannelProbeProcessor : public ChannelProbeProcessor
{
public:
    HookedChannelProbeProcessor();
    void indicate(ChannelLoad) override;

    HookRegistry<ChannelLoad> on_indication;

private:
    Hook<ChannelLoad> m_indication_hook;
};

} // namespace dcc
} // namespace vanetza

#endif /* HOOKED_CHANNEL_PROBE_PROCESSOR_HPP_M1O7VHKS */

