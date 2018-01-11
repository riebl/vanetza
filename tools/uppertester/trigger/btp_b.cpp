#include "btp.hpp"
#include "btp_b.hpp"
#include "uppertester.hpp"

using namespace vanetza;

void BtpBTrigger::process(UpperTester& tester, Socket& socket)
{
    BtpTriggerResult result;

    Application::DownPacketPtr packet { new DownPacket() };
    packet->layer(OsiLayer::Application) = ByteBuffer { };

    Application::DataRequest gn_request;
    gn_request.transport_type = geonet::TransportType::SHB;
    gn_request.communication_profile = geonet::CommunicationProfile::ITS_G5;

    btp::DataRequestB btp_request;
    btp_request.destination_port = host_cast<uint16_t>(destination_port);
    btp_request.destination_port_info = host_cast<uint16_t>(destination_port_info);
    btp_request.gn = gn_request;

    auto confirm = tester.request(btp_request, std::move(packet));

    if (confirm.accepted()) {
        result.result = 1;
    } else {
        result.result = 0;
    }

    socket.send(result);
}
