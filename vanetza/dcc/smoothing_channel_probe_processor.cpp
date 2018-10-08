#include "smoothing_channel_probe_processor.hpp"

namespace vanetza
{
namespace dcc
{

SmoothingChannelProbeProcessor::SmoothingChannelProbeProcessor(const OnUpdateFn& fn, UnitInterval alpha) :
    m_alpha(alpha), m_update_fn(fn)
{
}

void SmoothingChannelProbeProcessor::indicate(ChannelLoad cl)
{
    m_channel_load = m_alpha * cl + m_alpha.complement() * m_channel_load;
    if (m_update_fn) {
        m_update_fn(m_channel_load);
    }
}

ChannelLoad SmoothingChannelProbeProcessor::channel_load() const
{
    return m_channel_load;
}

} // namespace dcc
} // namespace vanetza
