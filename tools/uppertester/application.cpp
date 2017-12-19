#include "application.hpp"
#include <vanetza/btp/header.hpp>
#include <vanetza/btp/header_conversion.hpp>
#include <cassert>

using namespace vanetza;

Application::DataConfirm Application::request(const btp::DataRequestA& request, DownPacketPtr packet)
{
    DataConfirm confirm(DataConfirm::ResultCode::REJECTED_UNSPECIFIED);

    if (router && packet) {
        btp::HeaderA btp_header;
        btp_header.destination_port = request.destination_port;
        btp_header.source_port = request.source_port;
        packet->layer(OsiLayer::Transport) = btp_header;

        switch (request.gn.transport_type) {
            case geonet::TransportType::SHB: {
                geonet::ShbDataRequest shb(router->get_mib());
                copy_request_parameters(request, shb);
                confirm = router->request(shb, std::move(packet)); }
                break;
            default:
                // TODO remaining transport types are not implemented
                break;
        }
    }

    return confirm;
}

Application::DataConfirm Application::request(const btp::DataRequestB& request, DownPacketPtr packet)
{
    DataConfirm confirm(DataConfirm::ResultCode::REJECTED_UNSPECIFIED);

    if (router && packet) {
        btp::HeaderB btp_header;
        btp_header.destination_port = request.destination_port;
        btp_header.destination_port_info = request.destination_port_info;
        packet->layer(OsiLayer::Transport) = btp_header;

        switch (request.gn.transport_type) {
            case geonet::TransportType::SHB: {
                geonet::ShbDataRequest shb(router->get_mib());
                copy_request_parameters(request, shb);
                confirm = router->request(shb, std::move(packet)); }
                break;
            default:
                // TODO remaining transport types are not implemented
                break;
        }
    }

    return confirm;
}
