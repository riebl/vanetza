#include "application.hpp"
#include "dcc_passthrough.hpp"
#include "ethernet_device.hpp"
#include "router_context.hpp"
#include "time_trigger.hpp"
#include <vanetza/access/ethertype.hpp>
#include <vanetza/dcc/data_request.hpp>
#include <vanetza/dcc/interface.hpp>
#include <iostream>
#include <vanetza/common/byte_order.hpp>

using namespace vanetza;

RouterContext::RouterContext(const geonet::MIB& mib, TimeTrigger& trigger, vanetza::PositionProvider& positioning, vanetza::security::SecurityEntity* security_entity) :
    mib_(mib), router_(trigger.runtime(), mib_),
    trigger_(trigger), positioning_(positioning)
{
    router_.packet_dropped = std::bind(&RouterContext::log_packet_drop, this, std::placeholders::_1);
    router_.set_address(mib_.itsGnLocalGnAddr);
    router_.set_transport_handler(geonet::UpperProtocol::BTP_B, &dispatcher_);
    router_.set_security_entity(security_entity);
    update_position_vector();

    trigger_.schedule();
}

RouterContext::~RouterContext()
{
    for (auto* app : applications_) {
        disable(app);
    }
}

void RouterContext::log_packet_drop(geonet::Router::PacketDropReason reason)
{
    auto reason_string = stringify(reason);
    std::cout << "Router dropped packet because of " << reason_string << " (" << static_cast<int>(reason) << ")\n";
}

void RouterContext::set_link_layer(LinkLayer* link_layer)
{
    namespace dummy = std::placeholders;

    if (link_layer) {
        request_interface_.reset(new DccPassthrough { *link_layer, trigger_ });
        router_.set_access_interface(request_interface_.get());
        link_layer->indicate(std::bind(&RouterContext::indicate, this, dummy::_1, dummy::_2));
        update_packet_flow(router_.get_local_position_vector());
    } else {
        router_.set_access_interface(nullptr);
        request_interface_.reset();
    }
}

void RouterContext::indicate(CohesivePacket&& packet, const EthernetHeader& hdr)
{
    if (hdr.source != mib_.itsGnLocalGnAddr.mid() && hdr.type == access::ethertype::GeoNetworking) {
        std::cout << "received packet from " << hdr.source << " (" << packet.size() << " bytes)\n";
        std::unique_ptr<PacketVariant> up { new PacketVariant(std::move(packet)) };
        trigger_.schedule(); // ensure the clock is up-to-date for the security entity
        router_.indicate(std::move(up), hdr.source, hdr.destination);
        trigger_.schedule(); // schedule packet forwarding
    }
}

void RouterContext::enable(Application* app)
{
    app->router_ = &router_;

    dispatcher_.add_promiscuous_hook(app->promiscuous_hook());
    if (app->port() != btp::port_type(0)) {
        dispatcher_.set_non_interactive_handler(app->port(), app);
    }
}

void RouterContext::disable(Application* app)
{
    if (app->port() != btp::port_type(0)) {
        dispatcher_.set_non_interactive_handler(app->port(), nullptr);
    }
    dispatcher_.remove_promiscuous_hook(app->promiscuous_hook());

    app->router_ = nullptr;
}

void RouterContext::require_position_fix(bool flag)
{
    require_position_fix_ = flag;
    update_packet_flow(router_.get_local_position_vector());
}

void RouterContext::update_position_vector()
{
    router_.update_position(positioning_.position_fix());
    vanetza::Runtime::Callback callback = [this](vanetza::Clock::time_point) { this->update_position_vector(); };
    vanetza::Clock::duration next = std::chrono::seconds(1);
    trigger_.runtime().schedule(next, callback);
    trigger_.schedule();

    update_packet_flow(router_.get_local_position_vector());
}

void RouterContext::update_packet_flow(const geonet::LongPositionVector& lpv)
{
    if (request_interface_) {
        if (require_position_fix_) {
            // Skip all requests until a valid GPS position is available
            request_interface_->allow_packet_flow(lpv.position_accuracy_indicator);
        } else {
            request_interface_->allow_packet_flow(true);
        }
    }
}
