#ifndef GPS_POSITION_PROVIDER_HPP_GYN3GVQA
#define GPS_POSITION_PROVIDER_HPP_GYN3GVQA

#include "positioning.hpp"
#include <vanetza/common/clock.hpp>
#include <vanetza/common/position_provider.hpp>
#include <boost/asio/io_service.hpp>
#include <boost/asio/steady_timer.hpp>
#include <string>
#include <gps.h>

class GpsPositionProvider : public vanetza::PositionProvider
{
public:
    class GpsPositioningException : public PositioningException
    {
    protected:
        GpsPositioningException(int);
        friend class GpsPositionProvider;
    };

    GpsPositionProvider(boost::asio::io_service& io);
    GpsPositionProvider(boost::asio::io_service& io, const std::string& hostname, const std::string& port);
    ~GpsPositionProvider();

    const vanetza::PositionFix& position_fix() override;
    void fetch_position_fix();

private:
    void schedule_timer();
    void on_timer(const boost::system::error_code& ec);

    boost::asio::steady_timer timer_;
    gps_data_t gps_data;
    vanetza::PositionFix fetched_position_fix;
};

namespace gpsd
{

constexpr const char* default_port = DEFAULT_GPSD_PORT;
constexpr const char* shared_memory = GPSD_SHARED_MEMORY;

} // namespace gpsd

#endif /* GPS_POSITION_PROVIDER_HPP_GYN3GVQA */
