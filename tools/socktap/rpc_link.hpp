#pragma once

#include "link_layer.hpp"
#include <vanetza/access/interface.hpp>
#include <vanetza/rpc/asio_event_loop.hpp>
#include <vanetza/rpc/asio_event_port.hpp>
#include <vanetza/rpc/asio_stream.hpp>
#include <vanetza/rpc/link_layer_client.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/program_options/options_description.hpp>
#include <kj/async.h>

class RpcLinkLayer : public LinkLayer
{
public:
    /**
     * Create RPC link layer
     * \param io ASIO context
     * \param socket TCP socket connected to RPC server
     */
    RpcLinkLayer(boost::asio::io_context& io, boost::asio::ip::tcp::socket socket);
    ~RpcLinkLayer() noexcept;

    void request(const vanetza::access::DataRequest&, std::unique_ptr<vanetza::ChunkPacket>) override;
    void indicate(IndicationCallback) override;
    void set_source_address(const vanetza::MacAddress&) override;

    void radio_technology(const std::string&);
    void enable_debug(bool);
    static void add_options(boost::program_options::options_description&);

private:
    boost::asio::io_context& io_;
    vanetza::rpc::AsioEventPort event_port_;
    vanetza::rpc::AsioEventLoop event_loop_;
    vanetza::rpc::AsioStream asio_stream_;
    kj::WaitScope wait_scope_;
    vanetza::rpc::LinkLayerClient client_;
    IndicationCallback callback_;
};
