#ifndef NMEA_HPP_EJIHQ65L
#define NMEA_HPP_EJIHQ65L

#include <vanetza/units/angle.hpp>
#include <vanetza/units/velocity.hpp>
#include <vanetza/units/length.hpp>
#include <boost/date_time/posix_time/posix_time_types.hpp>
#include <cstdint>
#include <string>

namespace vanetza
{

// forward declaration
struct Wgs84Point;

namespace nmea
{
typedef boost::posix_time::ptime time;

enum class Quality
{
    Unavailable = 0,
    GPS = 1,
    DGPS = 2,
    PPS = 3,
    RTK = 4,
    Float_RTK = 5,
    Estimated = 6,
    Manual = 7,
    Simulation = 8
};

enum class RMCStatus : char
{
    Warning = 'V',
    Valid = 'A'
};

enum class FAAMode : char
{
    Autonomous = 'A',
    Differential = 'D',
    Estimated = 'E',
    Manual = 'M',
    Simulated = 'S',
    Invalid = 'N'
};

std::string gprmc(const time&, const Wgs84Point&, units::NauticalVelocity ground, units::TrueNorth heading);
std::string gpgga(const time&, const Wgs84Point&, Quality, units::Length hdop);
uint8_t checksum(std::string::const_iterator, std::string::const_iterator);

} // namespace nmea
} // namespace vanetza

#endif /* NMEA_HPP_EJIHQ65L */

