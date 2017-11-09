#include "application.hpp"
#include "dcc_passthrough.hpp"
#include "network_device.hpp"
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

geonet::MIB configure_mib(const NetworkDevice& device)
{
    geonet::MIB mib;
    mib.itsGnLocalGnAddr.mid(device.address());
    mib.itsGnLocalGnAddr.is_manually_configured(true);
    mib.itsGnLocalAddrConfMethod = geonet::AddrConfMethod::MANAGED;
    mib.itsGnSecurity = false;
    return mib;
}

RouterContext::RouterContext(raw_protocol::socket& socket, const NetworkDevice& device, TimeTrigger& trigger, PositionProvider& positioning) :
    mib_(configure_mib(device)), router_(trigger.runtime(), mib_),
    socket_(socket), device_(device), trigger_(trigger), positioning_(positioning),
    request_interface_(new DccPassthrough(socket, trigger)),
    receive_buffer_(2048, 0x00), receive_endpoint_(socket_.local_endpoint())
{
    router_.packet_dropped = std::bind(&RouterContext::log_packet_drop, this, std::placeholders::_1);
    router_.set_address(mib_.itsGnLocalGnAddr);
    router_.set_access_interface(request_interface_.get());
    router_.set_transport_handler(geonet::UpperProtocol::BTP_B, &dispatcher_);
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
    std::cout << "Router dropped packet because of " << static_cast<int>(reason) << "\n";
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

void RouterContext::update_position_vector()
{
    auto position = positioning_.current_position();

    router_.update(position);
    vanetza::Runtime::Callback callback = [this](vanetza::Clock::time_point) { this->update_position_vector(); };
    vanetza::Clock::duration next = std::chrono::seconds(1);
    trigger_.runtime().schedule(next, callback);
    trigger_.schedule();

    // Skip all requests until a valid GPS position is available
    request_interface_.get()->allow_packet_flow(position.position_accuracy_indicator);
}
