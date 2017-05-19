#include <vanetza/common/runtime.hpp>
#include <vanetza/geonet/dcc_information_sharing.hpp>
#include <vanetza/geonet/location_table.hpp>

namespace vanetza
{
namespace geonet
{

DccInformationSharing::DccInformationSharing(Runtime& rt, const LocationTable& lt, dcc::ChannelLoad target, UnitInterval delay) :
    m_runtime(rt), m_location_table(lt), m_cbr_target(target),
    m_trigger_interval(std::chrono::milliseconds(100)),
    m_last_aggregation(m_runtime.now()),
    on_global_cbr_update(m_update_hook)
{
    Clock::duration initial = m_trigger_interval;
    initial *= delay.value();
    m_runtime.schedule(initial, [this](const Clock::time_point&) { trigger(); });
}

DccInformationSharing::DccInformationSharing(Runtime& rt, const LocationTable& lt, dcc::ChannelLoad target) :
    DccInformationSharing(rt, lt, target, UnitInterval { 0.0 })
{
}

DccField DccInformationSharing::generate_dcc_field()
{
    DccMcoField dcc_mco;
    dcc_mco.local_cbr(m_aggregator.get_local_cbr());
    dcc_mco.neighbour_cbr(m_aggregator.get_one_hop_cbr());
    // TODO set transmission power
    return dcc_mco;
}

void DccInformationSharing::update_local_cbr(dcc::ChannelLoad local_cbr)
{
    m_cbr_local = local_cbr;
}

void DccInformationSharing::trigger()
{
    m_aggregator.aggregate(m_cbr_local, m_location_table, m_last_aggregation, m_cbr_target);
    m_last_aggregation = m_runtime.now();
    m_update_hook(static_cast<const CbrAggregator&>(m_aggregator));
    m_runtime.schedule(m_trigger_interval, [this](const Clock::time_point&) { trigger(); });
}

} // namespace geonet
} // namespace vanetza
