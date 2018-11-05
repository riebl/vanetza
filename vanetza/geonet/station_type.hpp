#ifndef STATION_TYPE_HPP_BARYX6ET
#define STATION_TYPE_HPP_BARYX6ET

namespace vanetza
{
namespace geonet
{

enum class StationType {
    Unknown = 0,
    Pedestrian = 1,
    Cyclist = 2,
    Moped = 3,
    Motorcycle = 4,
    Passenger_Car = 5,
    Bus = 6,
    Light_Truck = 7,
    Heavy_Truck = 8,
    Trailer = 9,
    Special_Vehicle = 10,
    Tram = 11,
    RSU = 15
};

} // namespace geonet
} // namespace vanetza

#endif /* STATION_TYPE_HPP_BARYX6ET */

