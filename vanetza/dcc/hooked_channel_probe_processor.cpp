#include "hooked_channel_probe_processor.hpp"

namespace vanetza
{
namespace dcc
{

HookedChannelProbeProcessor::HookedChannelProbeProcessor() :
    on_indication(m_indication_hook)
{
}

void HookedChannelProbeProcessor::indicate(ChannelLoad cl)
{
    m_indication_hook(cl);
}

} // namespace dcc
} // namespace vanetza
