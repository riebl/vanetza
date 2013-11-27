#include "nmea.hpp"
#include "wgs84point.hpp"
#include <cassert>
#include <cmath>
#include <iomanip>
#include <sstream>
#include <boost/date_time/gregorian/gregorian.hpp>
#include <boost/date_time/posix_time/posix_time.hpp>
#include <boost/format.hpp>

namespace vanetza
{
namespace nmea
{

/**
 * Print latitude data in BBBB.BBBB, b format.
 * BBBB.BBBB are degrees and minutes (ddmm.mm)
 * b is N or S
 */
void printLatitude(std::ostream& os, const Wgs84Point& point)
{
    double degrees = point.lat.value();
    double minutes = std::modf(std::abs(degrees), &degrees) * 60.0;
    os << boost::format("%02d%07.4f") % degrees % minutes;
    os << "," << (point.lat.value() >= 0.0 ? "N" : "S");
}

/**
 * Print longitude data in LLLL.LLLL, l format.
 * LLLL.LLLL are degrees and minutes (ddmm.mm)
 * l is E or W
 */
void printLongitude(std::ostream& os, const Wgs84Point& point)
{
    double degrees = point.lon.value();
    double minutes = std::modf(std::abs(degrees), &degrees) * 60.0;
    os << boost::format("%02d%07.4f") % degrees % minutes;
    os << "," << (point.lon.value() >= 0.0 ? "E" : "W");
}

namespace detail
{

struct latitude {
    const Wgs84Point& p;
    friend std::ostream& operator<<(std::ostream& os, const latitude& lat)
    {
        printLatitude(os, lat.p);
        return os;
    }
};

struct longitude {
    const Wgs84Point& p;
    friend std::ostream& operator<<(std::ostream& os, const longitude& lon)
    {
        printLongitude(os, lon.p);
        return os;
    }
};

} // namespace detail

detail::latitude latitude(const Wgs84Point& p) { return detail::latitude { p }; }
detail::longitude longitude(const Wgs84Point& p) { return detail::longitude { p}; }

/**
 * Finish NMEA sentence with *XX where XX is the calculated checksum
 * \param smsg NMEA sentence with leading $ but without trailing *XX
 * \return finished NMEA sentence
 */
std::string finish(std::stringstream& smsg)
{
    std::string msg = smsg.str();
    unsigned sum = checksum(++msg.begin(), msg.end());
    msg += boost::str(boost::format("*%02X") % static_cast<unsigned>(sum));
    return msg;
}

std::string gprmc(const time& ptime, const Wgs84Point& wgs84, VelocityKnot groundSpeed, AngleDegree heading)
{
    /**
     * Magnetic declination for central europe is about 1 degree east (2010), see this map for reference:
     * http://upload.wikimedia.org/wikipedia/commons/d/dd/World_Magnetic_Model_Main_Field_Declination_D_2010.png
     */
    const double magneticAngle = 1.0;
    const char magneticDirection = 'E';

    std::stringstream smsg;
    smsg << std::uppercase << std::fixed;
    auto* tfacet = new boost::posix_time::time_facet("%H%M%S");
    auto* dfacet = new boost::gregorian::date_facet("%d%m%y");
    smsg.imbue(std::locale(smsg.getloc(), tfacet));
    smsg.imbue(std::locale(smsg.getloc(), dfacet));

    smsg << "$GPRMC,";
    smsg << ptime << ","; // HHMMSS
    smsg << static_cast<char>(RMCStatus::VALID) << ",";
    smsg << latitude(wgs84) << "," << longitude(wgs84) << ",";
    smsg << std::setprecision(1) << groundSpeed.value() << ","; // GG.G
    smsg << std::setprecision(1) << std::fmod(heading.value(), 360.0) << ","; // RR.R
    smsg << ptime.date() << ","; // DDMMYY
    smsg << std::setprecision(1) << magneticAngle << "," << magneticDirection << ","; // M.M, E/W
    smsg << static_cast<char>(FAAMode::AUTONOMOUS);

    return finish(smsg);
}

std::string gpgga(const time& ptime, const Wgs84Point& wgs84, Quality quality, LengthMeter hdop)
{
    const unsigned numSatellites = 6; // Arbitrary number of used GPS satellites
    const double height = 0.0; // SUMO map is flat
    const double separation = 0.0; // Geoidal separation, can it be calculated?

    std::stringstream smsg;
    smsg << std::uppercase << std::fixed;
    auto* facet = new boost::posix_time::time_facet("%H%M%s");
    smsg.imbue(std::locale(smsg.getloc(), facet));

    smsg << "$GPGGA,";
    smsg << ptime << ","; // HHMMSS.ss
    smsg << latitude(wgs84) << "," << longitude(wgs84) << ",";
    smsg << static_cast<std::underlying_type<Quality>::type>(quality) << ","; // Q
    smsg << numSatellites << ","; // NN
    smsg << std::setprecision(1) << hdop.value() << ","; // D.D
    smsg << std::setprecision(1) << height << ",M,"; // H.H, h
    smsg << std::setprecision(1) << separation << ",M,"; // G.G, g
    smsg << ","; // AA, RRRR (both optional)

    return finish(smsg);
}

uint8_t checksum(std::string::const_iterator begin, std::string::const_iterator end)
{
    assert(begin <= end);
    uint8_t sum = 0;
    for (; begin != end; ++begin) {
        sum ^= *begin;
    }
    return sum;
}

} // namespace nmea
} // namespace vanetza

