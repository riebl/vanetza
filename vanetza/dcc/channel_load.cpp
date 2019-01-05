#include "channel_load.hpp"

namespace vanetza
{
namespace dcc
{

ChannelLoad::ChannelLoad(const UnitInterval& interval) :
    UnitInterval(interval)
{
}

ChannelLoad::ChannelLoad(unsigned probes_busy, unsigned probes_total) :
    UnitInterval(create_from_probes(probes_busy, probes_total))
{
}

UnitInterval ChannelLoad::create_from_probes(unsigned probes_busy, unsigned probes_total)
{
    double fraction = 0.0;
    if (probes_total != 0) {
        fraction = probes_busy;
        fraction /= probes_total;
    }

    return UnitInterval(fraction);
}

} // namespace dcc
} // namespace vanetza

