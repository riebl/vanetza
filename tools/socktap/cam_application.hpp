#ifndef CAM_APPLICATION_HPP_EUIC2VFR
#define CAM_APPLICATION_HPP_EUIC2VFR

#include "application.hpp"
#include <vanetza/common/position_provider.hpp>
#include <vanetza/common/clock.hpp>
#include <boost/asio/steady_timer.hpp>
#include <chrono>

class CamApplication : public Application
{
public:
    CamApplication(vanetza::PositionProvider& positioning, const vanetza::Clock::time_point& time_now, boost::asio::steady_timer&, std::chrono::milliseconds cam_interval);
    PortType port() override;
    void indicate(const DataIndication&, UpPacketPtr) override;

private:
    void schedule_timer();
    void on_timer(const boost::system::error_code& ec);

    vanetza::PositionProvider& positioning_;
    const vanetza::Clock::time_point& time_now_;
    std::chrono::milliseconds cam_interval_;
    boost::asio::steady_timer& timer_;
};

#endif /* CAM_APPLICATION_HPP_EUIC2VFR */
