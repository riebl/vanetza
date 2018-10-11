#ifndef LIMERIC_HPP_OPCJEHBN
#define LIMERIC_HPP_OPCJEHBN

#include <vanetza/common/clock.hpp>
#include <vanetza/common/hook.hpp>
#include <vanetza/common/unit_interval.hpp>
#include <vanetza/dcc/channel_load.hpp>
#include <vanetza/dcc/duty_cycle_permit.hpp>
#include <boost/circular_buffer.hpp>
#include <chrono>

namespace vanetza
{

// forward declaration
class Runtime;

namespace dcc
{

/**
 * LIMERIC adapted to ETSI ITS
 *
 * This implementation follows TS 102 687 v1.2.1 section 5.4
 */
class Limeric : public DutyCyclePermit
{
public:
    /**
     * Limeric paremeters as given by TS 102 687 v1.2.1, Table 3
     */
    struct Parameters
    {
        UnitInterval alpha { 0.016 };
        UnitInterval beta { 0.0012 };
        UnitInterval delta_max { 0.03 }; /*< upper bound permitted duty cycle */
        UnitInterval delta_min { 0.0006 }; /*< lower bound permitted duty cycle */
        double g_plus_max = 0.0005;
        double g_minus_max = -0.00025;
        ChannelLoad cbr_target { 0.68 };
        Clock::duration cbr_interval = std::chrono::milliseconds(100); /*< algorithm is scheduled every second interval */
    };

    Limeric(Runtime&);
    Limeric(Runtime&, const Parameters&);
    ~Limeric();

    /**
     * Report new channel load measurement
     * \param cl channel load measurement
     */
    void update_cbr(ChannelLoad);

    /**
     * Get current averaged CBR.
     * \note The result incorporates previous measurements as well as the averaged CBR during last periodic update.
     * \return averaged CBR
     */
    ChannelLoad average_cbr() const;

    /**
     * Get permitted duty cycle as calculated by the last periodic update
     * \return permitted duty cycle
     */
    UnitInterval permitted_duty_cycle() const override { return m_duty_cycle; }

    /**
     * Called every time the permitted duty cycle is updated
     * \param this instance itself
     * \param time point for which algorithm update has been scheduled
     */
    HookRegistry<const Limeric*, Clock::time_point> on_duty_cycle_change;

private:
    void calculate(Clock::time_point);
    void schedule();
    UnitInterval calculate_duty_cycle() const;

    Runtime& m_runtime;
    Parameters m_params;
    ChannelLoad m_channel_load; /*< moving average channel load */
    UnitInterval m_duty_cycle;
    boost::circular_buffer<ChannelLoad> m_cbr;
    Hook<const Limeric*, Clock::time_point> m_duty_cycle_change;
};

} // namespace dcc
} // namespace vanetza

#endif /* LIMERIC_HPP_OPCJEHBN */

