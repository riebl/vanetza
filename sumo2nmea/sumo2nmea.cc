#include "projector.h"
#include "gnss/nmea.h"
#include "gnss/wgs84point.h"
#include <iostream>
#include <string>
#include <boost/date_time/gregorian/gregorian.hpp>
#include <boost/date_time/posix_time/posix_time.hpp>
#include <boost/lexical_cast.hpp>

void printUsage(const char* exe, std::ostream& out = std::cout)
{
    out << "Usage: " << exe << " <projString> [offset_x offset_y]\n";
}

int main(int argc, const char** argv)
{
    const char* projString = nullptr;
    double netOffsetX = 0.0;
    double netOffsetY = 0.0;

    switch (argc) {
        case 4:
            netOffsetX = boost::lexical_cast<double>(argv[2]);
            netOffsetY = boost::lexical_cast<double>(argv[3]);
        case 2:
            projString = argv[1];
            break;
        default:
            printUsage(argv[0]);
            return 1;
    }

    Projector projector { projString };
    projector.offset(netOffsetX, netOffsetY);

    Wgs84Point point(49.01 % units::deg, 3.02 % units::deg);
    std::string nmeaMessage;

    while (true) {
        boost::gregorian::date date(boost::gregorian::day_clock::universal_day());
        boost::posix_time::ptime time(boost::posix_time::microsec_clock::universal_time());

        nmeaMessage = nmea::gprmc(time, point, VelocityKnot(10.3), AngleDegree(48.1), date);
        std::cout << nmeaMessage << "\r\n";
        nmeaMessage = nmea::gpgga(time, point, nmea::Quality::GPS, LengthMeter(0.0));
        std::cout << nmeaMessage << "\r\n";
        sleep(1);
        std::cout.flush();
    }

    return 0;
}
