#ifndef HEADER_TYPE_HPP_U5FGWR9N
#define HEADER_TYPE_HPP_U5FGWR9N

#include <cstdint>

namespace vanetza
{
namespace geonet
{

// forward declaration
struct Area;

enum class HeaderType : uint8_t
{
    Any = 0x00,
    Beacon = 0x10,
    GeoUnicast = 0x20,
    GeoAnycast_Circle = 0x30,
    GeoAnycast_Rect = 0x31,
    GeoAnycast_Elip = 0x32,
    GeoBroadcast_Circle = 0x40,
    GeoBroadcast_Rect = 0x41,
    GeoBroadcast_Elip = 0x42,
    TSB_Single_Hop = 0x50,
    TSB_Multi_Hop = 0x51,
    LS_Request = 0x60,
    LS_Reply = 0x61
};

HeaderType gbc_header_type(const Area&);
HeaderType gac_header_type(const Area&);

} // namespace geonet
} // namespace vanetza

#endif /* HEADER_TYPE_HPP_U5FGWR9N */

