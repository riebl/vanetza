#ifndef CHANNEL_LOAD_HPP_D1JOCNLP
#define CHANNEL_LOAD_HPP_D1JOCNLP

#include <vanetza/common/unit_interval.hpp>
#include <boost/operators.hpp>

namespace vanetza
{
namespace dcc
{

using ChannelLoad = UnitInterval;

struct ChannelLoadRational : boost::totally_ordered<ChannelLoadRational>
{
    ChannelLoadRational() :
        probes_above(0), probes_total(0) {}
    ChannelLoadRational(unsigned num, unsigned den) :
        probes_above(num), probes_total(den) {}
    unsigned probes_above;
    unsigned probes_total;

    UnitInterval fraction() const;
    bool operator<(const ChannelLoadRational&) const;
};

} // namespace dcc
} // namespace vanetza

#endif /* CHANNEL_LOAD_HPP_D1JOCNLP */

