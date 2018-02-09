#ifndef GPS_POSITION_PROVIDER_HPP_GYN3GVQA
#define GPS_POSITION_PROVIDER_HPP_GYN3GVQA

#include <vanetza/common/clock.hpp>
#include <vanetza/common/position_provider.hpp>
#include <stdexcept>
#include <string>
#include <gps.h>

class GpsPositionProvider : public vanetza::PositionProvider
{
public:
    class gps_error : public std::runtime_error
    {
    protected:
        gps_error(int);
        friend class GpsPositionProvider;
    };

    GpsPositionProvider();
    GpsPositionProvider(const std::string& hostname, const std::string& port);
    ~GpsPositionProvider();

    const vanetza::PositionFix& position_fix() override;
    void fetch_position_fix();

private:
    vanetza::Clock::time_point convert(timestamp_t) const;

    gps_data_t gps_data;
    vanetza::PositionFix fetched_position_fix;
};

namespace gpsd
{

constexpr char* default_port = DEFAULT_GPSD_PORT;
constexpr char* shared_memory = GPSD_SHARED_MEMORY;

} // namespace gpsd

#endif /* GPS_POSITION_PROVIDER_HPP_GYN3GVQA */

