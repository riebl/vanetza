#include "smoothing_channel_probe_processor.hpp"

namespace vanetza
{
namespace dcc
{

SmoothingChannelProbeProcessor::SmoothingChannelProbeProcessor(UnitInterval alpha) :
    m_alpha(alpha)
{
}

void SmoothingChannelProbeProcessor::indicate(ChannelLoad cl)
{
    m_channel_load = m_alpha * cl + m_alpha.complement() * m_channel_load;
    HookedChannelProbeProcessor::indicate(m_channel_load);
}

ChannelLoad SmoothingChannelProbeProcessor::channel_load() const
{
    return m_channel_load;
}

} // namespace dcc
} // namespace vanetza
