#include "channel_load.hpp"

namespace vanetza
{
namespace dcc
{

ChannelLoad ChannelLoadRational::fraction() const
{
    double fraction = 0.0;
    if (probes_total != 0) {
        fraction = probes_above;
        fraction /= probes_total;
    }
    return ChannelLoad(fraction);
}

bool ChannelLoadRational::operator<(const ChannelLoadRational& other) const
{
    return fraction() < other.fraction();
}

} // namespace dcc
} // namespace vanetza

