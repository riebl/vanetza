#ifndef DCC_INFORMATION_SHARING_HPP_GZCSHZLD
#define DCC_INFORMATION_SHARING_HPP_GZCSHZLD

#include <vanetza/common/clock.hpp>
#include <vanetza/common/hook.hpp>
#include <vanetza/common/unit_interval.hpp>
#include <vanetza/geonet/cbr_aggregator.hpp>
#include <vanetza/geonet/dcc_field_generator.hpp>

namespace vanetza
{

class Runtime;

namespace geonet
{

class LocationTable;

/**
 * DccInformationSharing realises the DCC_net behaviour for ITS-G5
 * \see TS 102 636-4-2 V1.1.1
 *
 * CBR_target mentioned in TS 102 636-4-2 V1.1.1 is probably the same constant as
 * NDL_maxChannelUse mentioned in TS 102 687 V1.1.1. However, no value is given:
 * Table A.3 in TS 102 687 declares them (implicitly through NDL_tmPacketArrivalrate) "n.a.".
 * Thus, we simply assume CBR_target = NDL_maxChannelUse = NDL_maxChannelLoad.
 */
class DccInformationSharing : public DccFieldGenerator
{
public:
    /**
     * Create DCC_net instance
     *
     * \param rt Runtime for scheduling periodic update cycles
     * \param lt Location Table with LocTEX_G5 entries
     * \param target CBR_target value (usually NDL_maxChannelLoad)
     * \param delay Delaying first update cycle randomly
     *
     * \note Set random delay interval when multiple stations are created at the same time!
     *       Values shall be distributed uniformly across full integer range.
     */
    DccInformationSharing(Runtime& rt, const LocationTable& lt, dcc::ChannelLoad target, UnitInterval delay);
    DccInformationSharing(Runtime& rt, const LocationTable& lt, dcc::ChannelLoad target);

    DccField generate_dcc_field() override;

    /**
     * Update local CBR measurement
     *
     * Local measurement rate is decoupled from processing in DCC_net,
     * i.e. DccInformationSharing buffers the given value and the latest
     * measurement value when its internal update cycle runs.
     *
     * \param cbr local CBR measurement
     */
    void update_local_cbr(dcc::ChannelLoad cbr);

private:
    void trigger();

    Runtime& m_runtime;
    const LocationTable& m_location_table;
    const dcc::ChannelLoad m_cbr_target;
    dcc::ChannelLoad m_cbr_local;
    CbrAggregator m_aggregator;
    Clock::duration m_trigger_interval;
    Timestamp m_last_aggregation;
    Hook<const CbrAggregator&> m_update_hook;

public:
    /**
     * on_global_cbr_update is called at each update cycle,
     * i.e. when a new global CBR has been calculated
     */
    HookRegistry<const CbrAggregator&> on_global_cbr_update;
};

} // namespace geonet
} // namespace vanetza

#endif /* DCC_INFORMATION_SHARING_HPP_GZCSHZLD */

