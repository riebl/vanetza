#ifndef NMEA_H_EJIHQ65L
#define NMEA_H_EJIHQ65L

#include "angle.h"
#include "velocity.h"
#include "length.h"
#include <cstdint>
#include <string>
#include <boost/date_time/gregorian/gregorian_types.hpp>
#include <boost/date_time/posix_time/posix_time_types.hpp>

struct Wgs84Point;

namespace nmea
{
    typedef boost::posix_time::ptime time;
    typedef boost::gregorian::date date;

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

    std::string gprmc(const time&, const Wgs84Point&, VelocityKnot ground, AngleDegree heading, const date&);
    std::string gpgga(const time&, const Wgs84Point&, Quality, LengthMeter hdop);
    uint8_t checksum(std::string::const_iterator, std::string::const_iterator);

} // namespace nmea

#endif /* NMEA_H_EJIHQ65L */

