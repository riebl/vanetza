#ifndef POSITION_UPDATER_HPP_KMWXTJRO
#define POSITION_UPDATER_HPP_KMWXTJRO

#include <vanetza/common/clock.hpp>
#include <vanetza/units/frequency.hpp>

namespace vanetza
{

// forward declarations
class Runtime;
class PositionProvider;
namespace geonet { class Router; }

namespace geonet
{

/**
 * PositionUpdater helps updating a Router's position vector periodically
 */
class PositionUpdater
{
public:
    /**
     * Create PositionUpdater scheduling position updates read from position provider
     * \note the default update rate is derived from router's MIB.
     * \param runtime where updater schedules its callback
     * \param pos position updates are read from this source
     * \param router position sink
     */
    PositionUpdater(Runtime& runtime, PositionProvider& pos, Router& router);
    ~PositionUpdater();

    /**
     * Change rate at which update is looking up new positions
     * \note MIB setting is not affected
     * \note an update interval smaller than zero disables updates
     * \param interval update interval
     */
    void update_rate(Clock::duration interval);
    void update_rate(units::Frequency);

private:
    void schedule();

    Runtime& m_runtime;
    PositionProvider& m_positioning;
    Router& m_router;
    Clock::duration m_interval;
};

} // namespace geonet
} // namespace vanetza

#endif /* POSITION_UPDATER_HPP_KMWXTJRO */

