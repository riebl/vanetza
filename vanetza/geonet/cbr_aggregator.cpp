#include <vanetza/geonet/cbr_aggregator.hpp>
#include <vanetza/geonet/location_table.hpp>
#include <vanetza/geonet/loctex_g5.hpp>
#include <algorithm>
#include <array>

namespace vanetza
{
namespace geonet
{

struct CbrAggregatorUnit
{
    CbrAggregatorUnit() : n(0) {}

    void operator+=(dcc::ChannelLoad cbr)
    {
        // calculate average as double so numerator can be larger than 1.0 temporarily
        average = dcc::ChannelLoad {(average.value() * n + cbr.value()) / (n + 1)};
        ++n;

        // >= comparison: second largest value might equal largest value
        if (cbr >= maximum[0]) {
            maximum[1] = maximum[0];
            maximum[0] = cbr;
        } else if (cbr > maximum[1]) {
            maximum[1] = cbr;
        }
    }

    dcc::ChannelLoad operator()(const dcc::ChannelLoad target) const
    {
        if (average > target) {
            return maximum[0];
        } else {
            return maximum[1];
        }
    }

    unsigned n;
    dcc::ChannelLoad average;
    std::array<dcc::ChannelLoad, 2> maximum;
};

CbrAggregator::CbrAggregator() :
    m_one_hop_cbr(0.0), m_two_hop_cbr(0.0)
{
}

void CbrAggregator::aggregate(ChannelLoad local, const LocationTable& lt, Timestamp lifetime, ChannelLoad target)
{
    m_local_cbr[1] = m_local_cbr[0];
    m_local_cbr[0] = local;

    CbrAggregatorUnit one_hop;
    CbrAggregatorUnit two_hop;

    LocationTable::entry_visitor entry_visitor =
        [&](const MacAddress&, const LocationTableEntry& entry) {
            const LocTEX_G5* loctex = entry.extensions.find<LocTEX_G5>();
            if (loctex && loctex->local_update >= lifetime) {
                one_hop += loctex->dcc_mco.local_cbr();
                two_hop += loctex->dcc_mco.neighbour_cbr();
            }
        };
    lt.visit(entry_visitor);

    m_one_hop_cbr = one_hop(target);
    m_two_hop_cbr = two_hop(target);
    m_global_cbr = std::max({ m_local_cbr[1], m_one_hop_cbr, m_two_hop_cbr});
}

} // namespace geonet
} // namespace vanetza
