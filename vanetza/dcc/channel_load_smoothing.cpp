#include "channel_load_smoothing.hpp"

namespace vanetza
{
namespace dcc
{

ChannelLoadSmoothing::ChannelLoadSmoothing() :
    m_alpha(0.5), m_smoothed(0.0)
{
}

ChannelLoadSmoothing::ChannelLoadSmoothing(ChannelLoad alpha) :
    m_alpha(alpha), m_smoothed(0.0)
{
}

void ChannelLoadSmoothing::update(ChannelLoad now)
{
    m_smoothed = m_alpha * now + m_alpha.complement() * m_smoothed;
}

} // namespace dcc
} // namespace vanetza
