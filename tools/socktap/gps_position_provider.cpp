#include "gps_position_provider.hpp"
#include <vanetza/units/angle.hpp>
#include <vanetza/common/confident_quantity.hpp>
#include <vanetza/units/velocity.hpp>
#include <vanetza/units/length.hpp>
#include <cmath>

static_assert(GPSD_API_MAJOR_VERSION >= 5 && GPSD_API_MAJOR_VERSION <= 9, "libgps has incompatible API");

namespace
{

#if GPSD_API_MAJOR_VERSION < 9
using gpsd_timestamp = timestamp_t;
#else
using gpsd_timestamp = timespec_t;
#endif

vanetza::Clock::time_point convert_gps_time(gpsd_timestamp gpstime)
{
    namespace posix = boost::posix_time;

    static const boost::gregorian::date posix_epoch(1970, boost::gregorian::Jan, 1);
#if GPSD_API_MAJOR_VERSION < 9
    // gpsd's timestamp_t is UNIX time (UTC) with fractional seconds
    const posix::time_duration::fractional_seconds_type posix_ticks(gpstime * posix::time_duration::ticks_per_second());
    const posix::ptime posix_time { posix_epoch, posix::time_duration(0, 0, 0, posix_ticks) };
#else
    // standard timespec_t is used from gpsd API version 9 on; use microsec for compatibility reasons
    const posix::ptime posix_time { posix_epoch, posix::seconds(gpstime.tv_sec) + posix::microsec(gpstime.tv_nsec / 1000) };
#endif

    // TAI has some seconds bias compared to UTC
    const auto tai_utc_bias = posix::seconds(37); // 37 seconds since 1st January 2017
    return vanetza::Clock::at(posix_time + tai_utc_bias);
}

} // namespace

GpsPositionProvider::GpsPositionProvider(boost::asio::steady_timer& timer) :
    GpsPositionProvider(timer, gpsd::shared_memory, nullptr)
{
}

GpsPositionProvider::GpsPositionProvider(boost::asio::steady_timer& timer, const std::string& hostname, const std::string& port) :
    timer_(timer)
{
    if (gps_open(hostname.c_str(), port.c_str(), &gps_data)) {
        throw gps_error(errno);
    }
    gps_stream(&gps_data, WATCH_ENABLE | WATCH_JSON, nullptr);
    schedule_timer();
}

GpsPositionProvider::~GpsPositionProvider()
{
    gps_stream(&gps_data, WATCH_DISABLE, nullptr);
    gps_close(&gps_data);
}

GpsPositionProvider::gps_error::gps_error(int err) :
    std::runtime_error(gps_errstr(err))
{
}

const vanetza::PositionFix& GpsPositionProvider::position_fix()
{
    return fetched_position_fix;
}

void GpsPositionProvider::schedule_timer()
{
    timer_.expires_from_now(std::chrono::milliseconds(500));
    timer_.async_wait(std::bind(&GpsPositionProvider::on_timer, this, std::placeholders::_1));
}

void GpsPositionProvider::on_timer(const boost::system::error_code& ec)
{
    if (ec == boost::asio::error::operation_aborted) {
        return;
    }

    fetch_position_fix();
    schedule_timer();
}

void GpsPositionProvider::fetch_position_fix()
{
    int gps_read_rc = 0;
    do {
#if GPSD_API_MAJOR_VERSION < 7
        gps_read_rc = gps_read(&gps_data);
#else
        gps_read_rc = gps_read(&gps_data, nullptr, 0);
#endif
    } while (gps_read_rc > 0 && gps_data.devices.ndevices > 0);

    if (gps_read_rc < 0) {
        throw gps_error(errno);
    }

    if (gps_data.status == STATUS_FIX && gps_data.fix.mode >= MODE_2D) {
        using namespace vanetza::units;
        static const TrueNorth north = TrueNorth::from_value(0.0);

        fetched_position_fix.timestamp = convert_gps_time(gps_data.fix.time);
        fetched_position_fix.latitude = gps_data.fix.latitude * degree;
        fetched_position_fix.longitude = gps_data.fix.longitude * degree;
        fetched_position_fix.speed.assign(gps_data.fix.speed * si::meter_per_second, gps_data.fix.eps * si::meter_per_second);
        fetched_position_fix.course.assign(north + gps_data.fix.track * degree, north + gps_data.fix.epd * degree);
        if (!std::isnan(gps_data.fix.epx) && !std::isnan(gps_data.fix.epy)) {
            if (gps_data.fix.epx > gps_data.fix.epy) {
                fetched_position_fix.confidence.semi_minor = gps_data.fix.epy * si::meter;
                fetched_position_fix.confidence.semi_major = gps_data.fix.epx * si::meter;
                fetched_position_fix.confidence.orientation = north + 90.0 * degree;
            } else {
                fetched_position_fix.confidence.semi_minor = gps_data.fix.epx * si::meter;
                fetched_position_fix.confidence.semi_major = gps_data.fix.epy * si::meter;
                fetched_position_fix.confidence.orientation = north;
            }
        } else {
            fetched_position_fix.confidence = vanetza::PositionConfidence();
        }
        if (gps_data.fix.mode == MODE_3D) {
            fetched_position_fix.altitude = vanetza::ConfidentQuantity<vanetza::units::Length>(gps_data.fix.altitude * si::meter, gps_data.fix.epv * si::meter);
        } else {
            fetched_position_fix.altitude = boost::none;
        }
    }
}

