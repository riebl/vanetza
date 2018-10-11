#include "limeric_transmit_rate_control.hpp"
#include <vanetza/common/runtime.hpp>

namespace vanetza
{
namespace dcc
{

LimericTransmitRateControl::LimericTransmitRateControl(const Runtime& rt, const Limeric& limeric) :
    m_budget(limeric, rt)
{
}

Clock::duration LimericTransmitRateControl::delay(const Transmission&)
{
    return m_budget.delay();
}

Clock::duration LimericTransmitRateControl::interval(const Transmission&)
{
    return m_budget.interval();
}

void LimericTransmitRateControl::notify(const Transmission& transmission)
{
    m_budget.notify(transmission.channel_occupancy());
}

void LimericTransmitRateControl::update()
{
    m_budget.update();
}

} // namespace dcc
} // namespace vanetza
