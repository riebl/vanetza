#ifndef CAM_APPLICATION_HPP_EUIC2VFR
#define CAM_APPLICATION_HPP_EUIC2VFR

#include "application.hpp"
#include <vanetza/asn1/cam.hpp>
#include <vanetza/common/position_provider.hpp>
#include <vanetza/common/runtime.hpp>
#include <boost/asio/steady_timer.hpp>
#include <chrono>

class CamApplication : public Application
{
public:
    //  Erik
    CamApplication(vanetza::PositionProvider& positioning, const vanetza::Runtime& rt, boost::asio::steady_timer&, std::chrono::milliseconds cam_intervall, bool print);
    PortType port() override;
    void indicate(const DataIndication&, UpPacketPtr) override;
    void printcam(vanetza::asn1::Cam message);
private:
    void schedule_timer();
    void on_timer(const boost::system::error_code& ec);
    // ERIK
    bool print_;
    vanetza::PositionProvider& positioning_;
    const vanetza::Runtime& runtime_;
    std::chrono::milliseconds cam_interval_;
    boost::asio::steady_timer& timer_;
};

#endif /* CAM_APPLICATION_HPP_EUIC2VFR */
