#ifndef NMEA_H_EJIHQ65L
#define NMEA_H_EJIHQ65L

#include <vanetza/units/angle.h>
#include <vanetza/units/velocity.h>
#include <vanetza/units/length.h>
#include <cstdint>
#include <string>
#include <boost/date_time/posix_time/posix_time_types.hpp>

namespace vanetza
{

struct Wgs84Point;

namespace nmea
{
    typedef boost::posix_time::ptime time;

    enum class Quality {
        UNAVAILABLE = 0,
        GPS = 1,
        DGPS = 2,
        PPS = 3,
        RTK = 4,
        FLOAT_RTK = 5,
        ESTIMATED = 6,
        MANUAL = 7,
        SIMULATION = 8
    };

    enum class RMCStatus : char {
        WARNING = 'V',
        VALID = 'A'
    };

    enum class FAAMode : char {
        AUTONOMOUS = 'A',
        DIFFERENTIAL = 'D',
        ESTIMATED = 'E',
        MANUAL = 'M',
        SIMULATED = 'S',
        INVALID = 'N'
    };

    std::string gprmc(const time&, const Wgs84Point&, VelocityKnot ground, AngleDegree heading);
    std::string gpgga(const time&, const Wgs84Point&, Quality, LengthMeter hdop);
    uint8_t checksum(std::string::const_iterator, std::string::const_iterator);

} // namespace nmea
} // namespace vanetza

#endif /* NMEA_H_EJIHQ65L */

