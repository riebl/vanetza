#include "application.hpp"
#include "dcc_passthrough.hpp"
#include "ethernet_device.hpp"
#include "position_provider.hpp"
#include "router_context.hpp"
#include "time_trigger.hpp"
#include <vanetza/dcc/data_request.hpp>
#include <vanetza/dcc/interface.hpp>
#include <vanetza/net/ethernet_header.hpp>
#include <boost/asio/generic/raw_protocol.hpp>
#include <iostream>

namespace asio = boost::asio;
using boost::asio::generic::raw_protocol;
using namespace vanetza;

RouterContext::RouterContext(raw_protocol::socket& socket, const geonet::MIB& mib, TimeTrigger& trigger, PositionProvider& positioning, vanetza::security::SecurityEntity& security_entity) :
    mib_(mib), router_(trigger.runtime(), mib_),
    socket_(socket), trigger_(trigger), positioning_(positioning),
    request_interface_(new DccPassthrough(socket, trigger)),
    receive_buffer_(2048, 0x00), receive_endpoint_(socket_.local_endpoint())
{
    router_.packet_dropped = std::bind(&RouterContext::log_packet_drop, this, std::placeholders::_1);
    router_.set_address(mib_.itsGnLocalGnAddr);
    router_.set_access_interface(request_interface_.get());
    router_.set_transport_handler(geonet::UpperProtocol::BTP_B, &dispatcher_);
    router_.set_security_entity(&security_entity);
    update_position_vector();

    do_receive();
    trigger_.schedule();
}

RouterContext::~RouterContext()
{
    for (auto* app : applications_) {
        app->router_ = nullptr;
    }
}

void RouterContext::log_packet_drop(geonet::Router::PacketDropReason reason)
{
    std::string reason_string;

    switch (reason) {
        case geonet::Router::PacketDropReason::PARSE_BASIC_HEADER:
            reason_string = "PARSE_BASIC_HEADER";
            break;
        case geonet::Router::PacketDropReason::PARSE_COMMON_HEADER:
            reason_string = "PARSE_COMMON_HEADER";
            break;
        case geonet::Router::PacketDropReason::PARSE_SECURED_HEADER:
            reason_string = "PARSE_SECURED_HEADER";
            break;
        case geonet::Router::PacketDropReason::PARSE_EXTENDED_HEADER:
            reason_string = "PARSE_EXTENDED_HEADER";
            break;
        case geonet::Router::PacketDropReason::ITS_PROTOCOL_VERSION:
            reason_string = "ITS_PROTOCOL_VERSION";
            break;
        case geonet::Router::PacketDropReason::DECAP_UNSUCCESSFUL_NON_STRICT:
            reason_string = "DECAP_UNSUCCESSFUL_NON_STRICT";
            break;
        case geonet::Router::PacketDropReason::DECAP_UNSUCCESSFUL_STRICT:
            reason_string = "DECAP_UNSUCCESSFUL_STRICT";
            break;
        case geonet::Router::PacketDropReason::HOP_LIMIT:
            reason_string = "HOP_LIMIT";
            break;
        case geonet::Router::PacketDropReason::PAYLOAD_SIZE:
            reason_string = "PAYLOAD_SIZE";
            break;
        case geonet::Router::PacketDropReason::SECURITY_ENTITY_MISSING:
            reason_string = "SECURITY_ENTITY_MISSING";
            break;
        default:
            reason_string = "UNKNOWN";
            break;
    }

    std::cout << "Router dropped packet because of " << reason_string << " (" << static_cast<int>(reason) << ")\n";
}

void RouterContext::do_receive()
{
    namespace sph = std::placeholders;
    socket_.async_receive_from(
            asio::buffer(receive_buffer_), receive_endpoint_,
            std::bind(&RouterContext::on_read, this, sph::_1, sph::_2));
}

void RouterContext::on_read(const boost::system::error_code& ec, std::size_t read_bytes)
{
    if (!ec) {
        ByteBuffer buffer(receive_buffer_.begin(), receive_buffer_.begin() + read_bytes);
        pass_up(CohesivePacket(std::move(buffer), OsiLayer::Link));
        do_receive();
    }
}

void RouterContext::pass_up(CohesivePacket&& packet)
{
    if (packet.size(OsiLayer::Link) < EthernetHeader::length_bytes) {
        std::cerr << "Router dropped invalid packet (too short)\n";
    } else {
        packet.set_boundary(OsiLayer::Link, EthernetHeader::length_bytes);
        auto link_range = packet[OsiLayer::Link];
        EthernetHeader hdr = decode_ethernet_header(link_range.begin(), link_range.end());
        if (hdr.source != mib_.itsGnLocalGnAddr.mid()) {
            std::cout << "received packet from " << hdr.source << " (" << packet.size() << " bytes)\n";
            std::unique_ptr<PacketVariant> up { new PacketVariant(std::move(packet)) };
            router_.indicate(std::move(up), hdr.source, hdr.destination);
            trigger_.schedule();
        }
    }
}

void RouterContext::enable(Application* app)
{
    app->router_ = &router_;
    dispatcher_.set_non_interactive_handler(app->port(), app);
}

void RouterContext::require_position_fix(bool flag)
{
    require_position_fix_ = flag;
    update_packet_flow(router_.get_local_position_vector());
}

void RouterContext::update_position_vector()
{
    auto position = positioning_.current_position();
    router_.update(position);
    vanetza::Runtime::Callback callback = [this](vanetza::Clock::time_point) { this->update_position_vector(); };
    vanetza::Clock::duration next = std::chrono::seconds(1);
    trigger_.runtime().schedule(next, callback);
    trigger_.schedule();

    update_packet_flow(position);
}

void RouterContext::update_packet_flow(const geonet::LongPositionVector& lpv)
{
    if (require_position_fix_) {
        // Skip all requests until a valid GPS position is available
        request_interface_->allow_packet_flow(lpv.position_accuracy_indicator);
    } else {
        request_interface_->allow_packet_flow(true);
    }
}

