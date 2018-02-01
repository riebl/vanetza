#include "hello_application.hpp"
#include <chrono>
#include <functional>
#include <iostream>

// This is a very simple application that sends BTP-B messages with the content 0xc0ffee.

using namespace vanetza;

HelloApplication::HelloApplication(boost::asio::steady_timer& timer, std::chrono::milliseconds interval) : timer_(timer), interval_(interval)
{
    schedule_timer();
}

HelloApplication::PortType HelloApplication::port()
{
    return host_cast<uint16_t>(42);
}

void HelloApplication::indicate(const DataIndication& indication, UpPacketPtr packet)
{
    std::cout << "Hello application received a packet" << std::endl;
}

void HelloApplication::schedule_timer()
{
    timer_.expires_from_now(interval_);
    timer_.async_wait(std::bind(&HelloApplication::on_timer, this, std::placeholders::_1));
}

void HelloApplication::on_timer(const boost::system::error_code& ec)
{
    if (ec != boost::asio::error::operation_aborted) {
        DownPacketPtr packet { new DownPacket() };
        packet->layer(OsiLayer::Application) = ByteBuffer { 0xC0, 0xFF, 0xEE };
        DataRequest request;
        request.transport_type = geonet::TransportType::SHB;
        request.communication_profile = geonet::CommunicationProfile::ITS_G5;
        request.its_aid = aid::CA;
        auto confirm = Application::request(request, std::move(packet));
        if (!confirm.accepted()) {
            throw std::runtime_error("Hello application data request failed");
        }

        schedule_timer();
    }
}
