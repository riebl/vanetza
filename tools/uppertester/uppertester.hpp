#ifndef UPPERTESTER_UPPERTESTER_HPP
#define UPPERTESTER_UPPERTESTER_HPP

#include "application.hpp"
#include "passthrough.hpp"
#include "socket.hpp"
#include "time_trigger.hpp"
#include <boost/asio/generic/raw_protocol.hpp>
#include <vanetza/btp/data_interface.hpp>
#include <vanetza/btp/data_indication.hpp>
#include <vanetza/btp/data_request.hpp>
#include <vanetza/btp/port_dispatcher.hpp>
#include <vanetza/geonet/data_confirm.hpp>
#include <vanetza/geonet/router.hpp>

class UpperTester : public Application
{
public:
    UpperTester(boost::asio::generic::raw_protocol::socket& raw_socket, TimeTrigger& trigger, const vanetza::geonet::MIB& mib);

    PortType port();

    void reset();

    void tap_packet(const DataIndication&, const vanetza::UpPacket&) override;

    void process_udp_trigger(vanetza::ByteBuffer& packet);

private:
    void do_receive();
    void on_read(const boost::system::error_code&, std::size_t);
    void pass_up(vanetza::CohesivePacket&&);

    void log_packet_drop(vanetza::geonet::Router::PacketDropReason);

    friend class Socket;

    TimeTrigger& m_trigger;
    const vanetza::geonet::MIB& mib;
    std::unique_ptr<Passthrough> request_interface;
    vanetza::btp::PortDispatcher dispatcher;
    Socket* socket;

    boost::asio::generic::raw_protocol::socket& raw_socket;
    boost::asio::generic::raw_protocol::endpoint receive_endpoint;
    vanetza::ByteBuffer receive_buffer;
};

#endif /* UPPERTESTER_UPPERTESTER_HPP */
