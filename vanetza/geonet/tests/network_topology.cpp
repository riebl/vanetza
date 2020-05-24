#include <vanetza/dcc/data_request.hpp>
#include <vanetza/dcc/interface.hpp>
#include <vanetza/geonet/areas.hpp>
#include <vanetza/geonet/data_confirm.hpp>
#include <vanetza/geonet/data_indication.hpp>
#include <vanetza/geonet/mib.hpp>
#include <vanetza/geonet/packet.hpp>
#include <vanetza/geonet/router.hpp>
#include <vanetza/geonet/timestamp.hpp>
#include <vanetza/geonet/tests/network_topology.hpp>
#include <vanetza/net/mac_address.hpp>
#include <boost/optional.hpp>
#include <GeographicLib/Geocentric.hpp>
#include <GeographicLib/Geodesic.hpp>
#include <GeographicLib/LocalCartesian.hpp>
#include <list>
#include <stdexcept>
#include <unordered_map>

namespace vanetza
{
namespace geonet
{

std::unique_ptr<UpPacket> duplicate_copy_construct(const ChunkPacket& packet)
{
    return std::unique_ptr<UpPacket> { new UpPacket(packet) };
}

std::unique_ptr<UpPacket> duplicate_serialize(const ChunkPacket& packet)
{
    ByteBuffer buf_packet;
    for (auto layer : osi_layer_range<OsiLayer::Network, OsiLayer::Application>()) {
        ByteBuffer buf_layer;
        packet[layer].convert(buf_layer);
        buf_packet.insert(buf_packet.end(), buf_layer.begin(), buf_layer.end());
    }
    assert(buf_packet.size() == packet.size(OsiLayer::Network, OsiLayer::Application));

    return std::unique_ptr<UpPacket> { new UpPacket(CohesivePacket(std::move(buf_packet), OsiLayer::Network)) };
}

NetworkTopology::RequestInterface::RequestInterface(NetworkTopology& network, const MacAddress& mac) :
    network(network), address(mac)
{
}

void NetworkTopology::RequestInterface::request(const dcc::DataRequest& req, std::unique_ptr<ChunkPacket> packet)
{
    ++requests;
    last_request = req;
    last_request.source = address;
    last_packet = std::move(packet);
    transmit();
}

void NetworkTopology::RequestInterface::reset()
{
    requests = 0;
    transmissions = 0;
    last_request = dcc::DataRequest {};
    last_packet.reset();
}

void NetworkTopology::RequestInterface::transmit()
{
    if (last_packet) {
        ++transmissions;
        network.save_request(last_request, std::unique_ptr<ChunkPacket> { new ChunkPacket(*last_packet) });
    }
}

void NetworkTopology::TransportHandler::indicate(const DataIndication& ind, std::unique_ptr<UpPacket> packet)
{
    ++counter;
    last_indication = ind;
    last_packet = std::move(packet);
}

void NetworkTopology::TransportHandler::reset()
{
    counter = 0;
    last_indication = DataIndication {};
    last_packet.reset();
}

NetworkTopology::RouterContext::RouterContext(NetworkTopology& network) :
    request_interface(network, mac_address),
    runtime(network.now),
    security(runtime),
    router(runtime, network.get_mib())
{
    router.set_access_interface(&request_interface);
    router.set_security_entity(&security.entity());
    router.set_transport_handler(UpperProtocol::IPv6, &transport_interface);
    set_position_accuracy_indicator(true);

    router.packet_dropped = [](Router::PacketDropReason pdr) {
        throw std::runtime_error("packet dropped unexpectedly: " + stringify(pdr));
    };
}

void NetworkTopology::RouterContext::set_position_accuracy_indicator(bool flag)
{
    const double pai_scaling = flag ? 0.25 : 0.75;
    position.confidence.semi_minor = pai_scaling * router.get_mib().itsGnPaiInterval;
    position.confidence.semi_major = pai_scaling * router.get_mib().itsGnPaiInterval;
    router.update_position(position);
    assert(router.get_local_position_vector().position_accuracy_indicator == flag);
}

NetworkTopology::NetworkTopology() : now(Clock::at("2016-02-29 23:59"))
{
    set_duplication_mode(PacketDuplicationMode::Copy_Construct);
    assert(fn_duplicate);
}

boost::optional<NetworkTopology::RouterContext&> NetworkTopology::get_host(const MacAddress& addr)
{
    boost::optional<RouterContext&> context;
    auto found = hosts.find(addr);
    if (found != hosts.end())
        context = *found->second;

    return context;
}

boost::optional<Router&> NetworkTopology::get_router(const MacAddress& addr)
{
    boost::optional<Router&> router;
    auto context = get_host(addr);
    if (context)
        router = context->router;

    return router;
}

boost::optional<NetworkTopology::RequestInterface&> NetworkTopology::get_interface(const MacAddress& addr)
{
    boost::optional<NetworkTopology::RequestInterface&> interface;
    auto context = get_host(addr);
    if (context)
        interface = context->request_interface;

    return interface;
}

boost::optional<NetworkTopology::TransportHandler&> NetworkTopology::get_transport(const MacAddress& addr)
{
    boost::optional<NetworkTopology::TransportHandler&> transport;
    auto context = get_host(addr);
    if (context)
        transport = context->transport_interface;
    return transport;
}

const unsigned& NetworkTopology::get_counter_requests(const MacAddress& addr)
{
    return counter_requests[addr];
}

void NetworkTopology::add_router(const MacAddress& addr)
{
    std::unique_ptr<RouterContext> context { new RouterContext(*this) };
    context->mac_address = addr;
    context->router.set_address(Address(context->mac_address));

    hosts.emplace(addr, std::move(context));
}

void NetworkTopology::add_reachability(const MacAddress& addr, std::initializer_list<MacAddress> new_reachables)
{
    // save reachable routers in reachability map
    std::set<MacAddress>& reachables = reachability[addr];
    for (const MacAddress& new_reachable : new_reachables) {
        reachables.insert(new_reachable);
    }
}

void NetworkTopology::save_request(const dcc::DataRequest& req, std::unique_ptr<ChunkPacket> packet)
{
    // save request with packet in list requests
    requests.emplace_back(now + network_delay, req, std::move(packet));

    // increment request counter
    counter_requests[req.source]++;
}

void NetworkTopology::dispatch()
{
    // process a stable sequence of saved requests
    decltype(requests) current_requests;
    std::swap(current_requests, requests);
    decltype(requests) skipped_requests;

    for (auto& tuple: current_requests) {
        // postpone transmission if its time has not yet come
        auto& timepoint = std::get<0>(tuple);
        if (timepoint > now) {
            skipped_requests.emplace_back(std::move(tuple));
            continue;
        }

        // extract request and packet from tuple
        auto& req = std::get<1>(tuple);
        auto& packet = std::get<2>(tuple);

        auto neighbours = reachability[req.source];
        // broadcast packet to all reachable routers
        if (req.destination == cBroadcastMacAddress) {
            for (auto& mac: neighbours) {
                auto router = get_router(mac);
                if (router) {
                    send(*router, req.source, req.destination, *packet);
                }
            }
        }
        // send packet only to specific destination router
        else if (neighbours.find(req.destination) != neighbours.end()) {
            auto router = get_router(req.destination);
            if (router) {
                send(*router, req.source, req.destination, *packet);
            }
        }
    }

    // move all skipped requests to head of pending requests
    requests.splice(requests.begin(), std::move(skipped_requests));
}

void NetworkTopology::send(Router& receiver, const MacAddress& sender, const MacAddress& destination, const ChunkPacket& packet)
{
    assert(sender != destination);
    counter_indications++;
    std::unique_ptr<UpPacket> packet_up = fn_duplicate(packet);
    receiver.indicate(std::move(packet_up), sender, destination);
}

void NetworkTopology::set_position(const MacAddress& addr, CartesianPosition c)
{
    // convert cartesian to geodetic position
    GeodeticPosition pos = convert_cartesian_geodetic(c);
    auto host = get_host(addr);
    if (host) {
        host->position.timestamp = now;
        host->position.latitude = pos.latitude;
        host->position.longitude = pos.longitude;
        host->router.update_position(host->position);
        host->security.set_accurate_position(host->position.latitude, host->position.longitude);
    }
}

void NetworkTopology::advance_time(Clock::duration t)
{
    do {
        auto next = next_event();
        const auto step = std::min(t, next - now);
        now += step;
        t -= step;
        // update timestamp for every router
        for (auto& kv : hosts) {
            RouterContext& host = *kv.second;
            host.runtime.trigger(now);
            host.position.timestamp = now;
            host.router.update_position(host.position);
        }
        dispatch();
    } while (t.count() > 0);
}

Clock::time_point NetworkTopology::next_event() const
{
    // next event may be pending link layer request
    Clock::time_point next = requests.empty() ? Clock::time_point::max() : std::get<0>(requests.front());

    for (auto& kv : hosts) {
        RouterContext& host = *kv.second;
        if (host.runtime.next() > now && host.runtime.next() < next) {
            next = host.runtime.next();
        }
    }

    return next;
}

void NetworkTopology::reset_counters()
{
    counter_indications = 0;
    counter_requests.clear();

    requests.clear();
    for (auto& host : hosts) {
        RouterContext* ctx = std::get<1>(host).get();
        ctx->request_interface.reset();
        ctx->transport_interface.reset();
    }
}

void NetworkTopology::set_duplication_mode(PacketDuplicationMode mode)
{
    switch (mode) {
        case PacketDuplicationMode::Copy_Construct:
            fn_duplicate = &duplicate_copy_construct;
            break;
        case PacketDuplicationMode::Serialize:
            fn_duplicate = &duplicate_serialize;
            break;
        default:
            throw std::runtime_error("Invalid PacketDuplicationMode");
            break;
    }
}

void NetworkTopology::set_network_delay(Clock::duration delay)
{
    network_delay = delay;
}

void NetworkTopology::build_fully_meshed_reachability()
{
    reachability.clear();
    for (auto& outer : hosts) {
        for (auto& inner : hosts) {
            if (outer != inner) {
                reachability[outer.first].insert(inner.first);
            }
        }
    }
}

GeodeticPosition convert_cartesian_geodetic(const CartesianPosition& cart)
{
    using namespace vanetza::units;
    using namespace vanetza::units::si;

    const GeographicLib::Geocentric& earth = GeographicLib::Geocentric::WGS84();
    double lat = 0.0, lon = 0.0, unused_h = 0.0;
    GeographicLib::LocalCartesian proj(lat, lon, unused_h, earth);
    double x = cart.x / meter;
    double y = cart.y / meter;
    double unused_z = 0.0;
    proj.Reverse(x, y, unused_z, lat, lon, unused_h);

    return GeodeticPosition(lat * degree, lon * degree);
}

Area circle_dest_area(units::Length radius, units::Length midpoint_x, units::Length midpoint_y)
{
    using namespace vanetza::units;
    using namespace vanetza::units::si;

    Area dest_area;
    Circle c;
    c.r = radius;
    dest_area.shape = c;
    dest_area.position = convert_cartesian_geodetic(CartesianPosition(midpoint_x, midpoint_y));

    return dest_area;
}

} // namespace geonet
} // namespace vanetza
