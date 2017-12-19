#include "trigger/btp_a.hpp"
#include "trigger/btp_b.hpp"
#include "trigger/common_ut_initialize.hpp"
#include "trigger/common_change_position.hpp"
#include "trigger/common_change_pseudonym.hpp"
#include "serialization.hpp"
#include "uppertester.hpp"
#include <boost/algorithm/hex.hpp>
#include <boost/optional.hpp>
#include <vanetza/btp/header.hpp>
#include <vanetza/btp/header_conversion.hpp>
#include <vanetza/common/byte_order.hpp>
#include <vanetza/net/ethernet_header.hpp>
#include <cassert>
#include <iostream>

using namespace vanetza;
namespace asio = boost::asio;
using boost::asio::generic::raw_protocol;

UpperTester::UpperTester(boost::asio::generic::raw_protocol::socket& raw_socket, TimeTrigger& trigger, const vanetza::geonet::MIB& mib)
    : raw_socket(raw_socket), m_trigger(trigger), mib(mib), request_interface(new Passthrough(raw_socket)), receive_buffer(2048, 0x00)
{
    dispatcher.set_interactive_handler(this->port(), this);
    dispatcher.set_non_interactive_handler(this->port(), this);

    do_receive();
    trigger.schedule();
}

void UpperTester::do_receive()
{
    raw_socket.async_receive_from(
            asio::buffer(receive_buffer), receive_endpoint,
            std::bind(&UpperTester::on_read, this, std::placeholders::_1, std::placeholders::_2));
}

void UpperTester::on_read(const boost::system::error_code& ec, std::size_t read_bytes)
{
    if (!ec) {
        std::cout << ">>> Raw Ethernet Frame (" << read_bytes << " bytes)" << std::endl;

        ByteBuffer buffer(receive_buffer.begin(), receive_buffer.begin() + read_bytes);
        pass_up(CohesivePacket(std::move(buffer), OsiLayer::Physical));
        do_receive();
    }
}

void UpperTester::pass_up(CohesivePacket&& packet)
{
    if (!router) {
        return;
    }

    packet.set_boundary(OsiLayer::Physical, 0);

    if (packet.size(OsiLayer::Link) < EthernetHeader::length_bytes) {
        std::cerr << "UpperTester dropped invalid packet (too short for Ethernet header)" << std::endl;
    } else {
        packet.set_boundary(OsiLayer::Link, EthernetHeader::length_bytes);
        auto link_range = packet[OsiLayer::Link];
        EthernetHeader hdr = decode_ethernet_header(link_range.begin(), link_range.end());
        if (hdr.source != mib.itsGnLocalGnAddr.mid()) {
            std::cout << "Received packet from " << hdr.source << " (" << packet.size() << " bytes)" << std::endl;
            std::unique_ptr<PacketVariant> up { new PacketVariant(std::move(packet)) };
            m_trigger.schedule(); // ensure the clock is up-to-date for the security entity
            router->indicate(std::move(up), hdr.source, hdr.destination);
            m_trigger.schedule(); // schedule packet forwarding
        }
    }
}

void UpperTester::log_packet_drop(geonet::Router::PacketDropReason reason)
{
    auto reason_string = stringify(reason);
    std::cout << "Router dropped packet because of " << reason_string << " (" << static_cast<int>(reason) << ")" << std::endl;
}

UpperTester::PortType UpperTester::port()
{
    return host_cast<uint16_t>(4000); // port used by tests
}

void UpperTester::indicate(const DataIndication& indication, UpPacketPtr packet)
{
    BtpEventIndication btp_event;

    auto byte_range = boost::create_byte_view(*packet, OsiLayer::Session);
    ByteBuffer payload_buffer(byte_range.begin(), byte_range.end());
    btp_event.packet = payload_buffer;

    std::cout << ">>> BTP received: ";
    boost::algorithm::hex(payload_buffer.begin(), payload_buffer.end(), std::ostream_iterator<char>(std::cout));
    std::cout << " (" << payload_buffer.size() << " bytes)" << std::endl;

    ByteBuffer buffer;
    serialize_into_buffer(btp_event, buffer);
    socket->send(buffer);
}

void UpperTester::process_udp_trigger(ByteBuffer& packet)
{
    std::cout << "UpperTester received an UDP packet (" << packet.size() << " bytes)" << std::endl;

    if (packet.size() < 1) {
        std::cerr << "Ignoring packet, because it is too short." << std::endl;
        return;
    }

    uint8_t type = packet.at(0);
    Trigger *trigger;

    if (type == 0x00) {
        trigger = new UtInitializeTrigger();
    } else if (type == 0x02) {
        trigger = new ChangePositionTrigger();
    } else if (type == 0x04) {
        trigger = new ChangePseudonymTrigger();
    } else if (type == 0x70) {
        trigger = new BtpATrigger();
    } else if (type == 0x71) {
        trigger = new BtpBTrigger();
    } else {
        std::cerr << "Unknown packet type: " << type << std::endl;
        return;
    }

    if (!trigger->deserialize(packet)) {
        std::cerr << "Error during deserialization." << std::endl;
        return;
    }

    if (type == 0x00) {
        UtInitializeTrigger *input = (UtInitializeTrigger*) trigger;
        std::cout << "Processing initialize trigger..." << std::endl;

        if (router) {
            delete router;
        }

        router = new geonet::Router(m_trigger.runtime(), mib);
        router->set_address(mib.itsGnLocalGnAddr);
        router->set_access_interface(request_interface.get());
        router->set_transport_handler(geonet::UpperProtocol::BTP_A, &dispatcher);
        router->set_transport_handler(geonet::UpperProtocol::BTP_B, &dispatcher);
        router->packet_dropped = std::bind(&UpperTester::log_packet_drop, this, std::placeholders::_1);

        UtInitializeResult result;
        result.result = 1; // Success

        ByteBuffer buffer;
        serialize_into_buffer(result, buffer);
        socket->send(buffer);
    } else if (type == 0x70) {
        BtpATrigger *input = (BtpATrigger*) trigger;
        BtpTriggerResult result;
        result.result = 0;

        if (router) {
            DownPacketPtr packet { new DownPacket() };
            packet->layer(OsiLayer::Application) = ByteBuffer { };

            DataRequest gn_request;
            gn_request.transport_type = geonet::TransportType::SHB;
            gn_request.communication_profile = geonet::CommunicationProfile::ITS_G5;

            btp::DataRequestA btp_request;
            btp_request.destination_port = host_cast<uint16_t>(input->destination_port);
            btp_request.source_port = host_cast<uint16_t>(input->source_port);
            btp_request.gn = gn_request;

            auto confirm = request(btp_request, std::move(packet));

            if (confirm.accepted()) {
                result.result = 1;
            }
        }

        ByteBuffer buffer;
        serialize_into_buffer(result, buffer);
        socket->send(buffer);
    } else if (type == 0x71) {
        BtpBTrigger *input = (BtpBTrigger*) trigger;
        BtpTriggerResult result;
        result.result = 0;

        if (router) {
            DownPacketPtr packet { new DownPacket() };
            packet->layer(OsiLayer::Application) = ByteBuffer { };

            DataRequest gn_request;
            gn_request.transport_type = geonet::TransportType::SHB;
            gn_request.communication_profile = geonet::CommunicationProfile::ITS_G5;

            btp::DataRequestB btp_request;
            btp_request.destination_port = host_cast<uint16_t>(input->destination_port);
            btp_request.destination_port_info = host_cast<uint16_t>(input->destination_port_info);
            btp_request.gn = gn_request;

            auto confirm = request(btp_request, std::move(packet));

            if (confirm.accepted()) {
                result.result = 1;
            }
        }

        ByteBuffer buffer;
        serialize_into_buffer(result, buffer);
        socket->send(buffer);
    } else {
        std::cerr << "Packet handling not implemented!" << std::endl;
    }
}
