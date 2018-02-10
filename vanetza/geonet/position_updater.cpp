#include <vanetza/common/position_provider.hpp>
#include <vanetza/common/runtime.hpp>
#include <vanetza/geonet/position_updater.hpp>
#include <vanetza/geonet/router.hpp>
#include <vanetza/units/time.hpp>
#include <chrono>

namespace vanetza
{
namespace geonet
{

PositionUpdater::PositionUpdater(Runtime& rt, PositionProvider& position, Router& router) :
    m_runtime(rt), m_positioning(position), m_router(router)
{
    update_rate(m_router.get_mib().itsGnMinimumUpdateFrequencyEPV);
}

PositionUpdater::~PositionUpdater()
{
    m_runtime.cancel(this);
}

void PositionUpdater::schedule()
{
    if (m_interval > Clock::duration::zero()) {
        m_runtime.schedule(m_interval, [this](Clock::time_point) {
                m_router.update_position(m_positioning.position_fix());
                schedule();
        }, this);
    }
}

void PositionUpdater::update_rate(Clock::duration interval)
{
    m_interval = interval;
    m_runtime.cancel(this); /*< cancel previously scheduled callback */
    schedule();
}

void PositionUpdater::update_rate(units::Frequency rate)
{
    if (rate > units::Frequency::from_value(0.0)) {
        using namespace std::chrono;
        const duration<double> interval { 1.0 / rate / units::si::second };
        update_rate(duration_cast<Clock::duration>(interval));
    } else {
        update_rate(Clock::duration::zero());
    }
}

} // namespace geonet
} // namespace vanetza
