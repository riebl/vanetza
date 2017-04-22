#ifndef LOCTEX_G5_HPP_BVRKEPHW
#define LOCTEX_G5_HPP_BVRKEPHW

#include <vanetza/geonet/dcc_mco_field.hpp>
#include <vanetza/geonet/timestamp.hpp>

namespace vanetza
{
namespace geonet
{

/**
 * Media-dependent extension to the Location Table Entry (LocTE) for ITS-G5
 */
struct LocTEX_G5
{
    Timestamp local_update; /*< TST_G5: last update time (local time stamp) */
    Timestamp source_update; /*< TST_SO_PV_G5: SO PV timestamp from SHB header */
    DccMcoField dcc_mco;
};

} // namespace geonet
} // namespace vanetza

#endif /* LOCTEX_G5_HPP_BVRKEPHW */

