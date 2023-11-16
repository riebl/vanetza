#include "cube_evk_link.hpp"

#include <iostream>
#include <vanetza/net/osi_layer.hpp>
#include <vanetza/net/packet_variant.hpp>
#include <vanetza/net/cohesive_packet.hpp>
#include <vanetza/access/data_request.hpp>
#include <vanetza/common/byte_view.hpp>
#include <vanetza/access/ethertype.hpp>

#include <boost/asio/placeholders.hpp>
#include <boost/bind/bind.hpp>

CubeEvkLink::CubeEvkLink(boost::asio::io_service& io, boost::asio::ip::address_v4 radio_ip)
    : io_(io), tx_socket_(io), rx_socket_(io)
{
    const boost::asio::ip::udp::endpoint radio_endpoint_tx(radio_ip, cube_evk_radio_port_tx);
    tx_socket_.connect(radio_endpoint_tx);

    boost::asio::ip::udp::endpoint radio_endpoint_rx(boost::asio::ip::udp::v4(), cube_evk_radio_port_rx);
    rx_socket_.open(radio_endpoint_rx.protocol());
    rx_socket_.bind(radio_endpoint_rx);

    rx_socket_.async_receive_from(
        boost::asio::buffer(received_data_), host_endpoint_,
        boost::bind(&CubeEvkLink::handle_packet_received, this, boost::asio::placeholders::error, boost::asio::placeholders::bytes_transferred));

}

void CubeEvkLink::handle_packet_received(const boost::system::error_code& ec, size_t bytes) 
{   
    if (!ec) 
    {
        vanetza::ByteBuffer buf(received_data_.begin(), received_data_.begin() + bytes);

        GossipMessage gossipMessage;
        gossipMessage.ParseFromArray(buf.data(), buf.size());

        switch (gossipMessage.kind_case()) 
        {
            case GossipMessage::KindCase::kCbr:
            {
                // got CBR; use this for your DCC
                // const ChannelBusyRatio& cbr = gossipMessage.cbr();
                // vanetza::dcc::ChannelLoad(cbr.busy(), cbr.total())
                break;
            }
            case GossipMessage::KindCase::kLinklayerRx:
            {
                pass_message_to_router(std::unique_ptr<LinkLayerReception>{gossipMessage.release_linklayer_rx()});
                break;
            }
            default:
            {
                std::cerr << "Received GossipMessage of unknown kind " << gossipMessage.kind_case() << std::endl;
            }
        }

        rx_socket_.async_receive_from(
            boost::asio::buffer(received_data_), host_endpoint_,
            boost::bind(&CubeEvkLink::handle_packet_received, this, boost::asio::placeholders::error, boost::asio::placeholders::bytes_transferred));

    }
    else
    {
        std::cerr << "CubeEvkLink::handle_packet_received went wrong: " << ec << std::endl;
    }

}

void CubeEvkLink::request(const vanetza::access::DataRequest& request, std::unique_ptr<vanetza::ChunkPacket> packet)
{
    CommandRequest command;
    command.set_allocated_linklayer_tx(create_link_layer_tx(request, std::move(packet)).release());
    
    std::string serializedTransmission;
    command.SerializeToString(&serializedTransmission);
    tx_socket_.send(boost::asio::buffer(serializedTransmission));
}

void CubeEvkLink::indicate(IndicationCallback callback)
{
    indicate_to_router_ = callback;
}

void CubeEvkLink::pass_message_to_router(std::unique_ptr<LinkLayerReception> packet)
{
    if (packet->source().size() != vanetza::MacAddress::length_bytes) 
    {
        std::cerr << "received packet's source MAC address is invalid" << std::endl;
    } 
    else if (packet->destination().size() != vanetza::MacAddress::length_bytes) 
    {
        std::cerr << "received packet's destination MAC address is invalid"  << std::endl;
    } 
    else 
    {
        vanetza::EthernetHeader ethernet_header;
        std::copy_n(packet->source().begin(), vanetza::MacAddress::length_bytes, ethernet_header.source.octets.begin());
        std::copy_n(packet->destination().begin(), vanetza::MacAddress::length_bytes, ethernet_header.destination.octets.begin());
        ethernet_header.type = vanetza::access::ethertype::GeoNetworking;

        vanetza::ByteBuffer buffer(packet->payload().begin(), packet->payload().end());
        vanetza::CohesivePacket packet(std::move(buffer), vanetza::OsiLayer::Network);

        indicate_to_router_(std::move(packet), ethernet_header);
    }
}

std::unique_ptr<LinkLayerTransmission> CubeEvkLink::create_link_layer_tx(const vanetza::access::DataRequest& req, std::unique_ptr<vanetza::ChunkPacket> packet)
{
    using namespace vanetza;

    std::unique_ptr<LinkLayerTransmission> transmission{new LinkLayerTransmission()};
    transmission->set_source(req.source_addr.octets.data(), req.source_addr.octets.size());
    transmission->set_destination(req.destination_addr.octets.data(), req.destination_addr.octets.size());

    LinkLayerPriority prio = LinkLayerPriority::BEST_EFFORT;
    switch (req.access_category) 
    {
        case access::AccessCategory::VO:
            prio = LinkLayerPriority::VOICE;
            break;
        case access::AccessCategory::VI:
            prio = LinkLayerPriority::VIDEO;
            break;
        case access::AccessCategory::BE:
            prio = LinkLayerPriority::BEST_EFFORT;
            break;
        case access::AccessCategory::BK:
            prio = LinkLayerPriority::BACKGROUND;
            break;
        default:
            std::cerr << "Unknown access category requested, falling back to best effort!" << std::endl;
            break;
    }
    transmission->set_priority(prio);

    std::string* payload = transmission->mutable_payload();
    for (auto& layer : osi_layer_range<OsiLayer::Network, OsiLayer::Application>()) 
    {
        auto byte_view = create_byte_view(packet->layer(layer));
        payload->append(byte_view.begin(), byte_view.end());
    }

    return transmission;
}