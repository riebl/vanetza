#include "rpc_link.hpp"
#include "vanetza/rpc/link_layer_client.hpp"
#include "vanetza/rpc/logger.hpp"
#include <vanetza/access/ethertype.hpp>
#include <iostream>

namespace {

class RpcLinkLayerLogger : public vanetza::rpc::Logger
{
public:
    void error(const char* module, const char* message) override
    {
        std::cerr << "RPC error at " << module << ": " << message << "\n";
    }

    void debug(const char* module, const char* message) override
    {
        if (print_debug_) {
           std::cout << "RPC debug(" << module << "): " << message << "\n";
        }
    }

    void enable_debug(bool debug)
    {
        print_debug_ = debug;
    }

private:
    bool print_debug_ = false;
};

RpcLinkLayerLogger logger;

} // namespace

RpcLinkLayer::RpcLinkLayer(boost::asio::io_context& io, boost::asio::ip::tcp::socket socket) :
    io_(io),
    event_port_(io),
    event_loop_(event_port_),
    asio_stream_(std::move(socket)),
    wait_scope_(event_loop_),
    client_(event_port_.getTimer(), asio_stream_, &logger)
{
    auto id = client_.identify().then([](const vanetza::rpc::LinkLayerClient::Identity& identity) -> kj::Promise<void> {
        std::cout << "Connected to RPC server id=" << identity.id << " version=" << identity.version << "\n";
        if (!identity.info.empty()) {
          std::cout << "RPC server's info: " << identity.info << "\n";
        }
        return kj::READY_NOW;
    });
    client_.add_task(kj::mv(id));
}

RpcLinkLayer::~RpcLinkLayer() noexcept
{
}

void RpcLinkLayer::set_source_address(const vanetza::MacAddress& addr)
{
    client_.set_source_address(addr);
}

void RpcLinkLayer::request(const vanetza::access::DataRequest& request, std::unique_ptr<vanetza::ChunkPacket> packet)
{
    client_.request(request, std::move(packet));
}

void RpcLinkLayer::indicate(IndicationCallback callback)
{
    if (callback) {
        auto wrapper = [callback, this](vanetza::rpc::LinkLayerClient::Indication&& indication) {
            boost::asio::post(io_, [callback, indication]() mutable {
                vanetza::EthernetHeader eth_hdr;
                eth_hdr.destination = indication.destination;
                eth_hdr.source = indication.source;
                eth_hdr.type = vanetza::access::ethertype::GeoNetworking;
                callback(std::move(indication.packet), eth_hdr);
            });
        };
        client_.indicate(std::move(wrapper));
    } else {
        client_.indicate(nullptr);
    }
}

void RpcLinkLayer::radio_technology(const std::string& technology)
{
    if (technology == "ITS-G5") {
        client_.configure(vanetza::rpc::LinkLayerClient::Technology::ITS_G5);
    } else if (technology == "LTE-V2X" || technology == "C-V2X") {
        client_.configure(vanetza::rpc::LinkLayerClient::Technology::LTE_V2X);
    } else if (!technology.empty()) {
        std::cerr << "Unknown radio technology '" << technology << "'. RPC link layer omits radio-specific fields.\n";
    }
}

void RpcLinkLayer::enable_debug(bool debug)
{
    logger.enable_debug(debug);
}

void RpcLinkLayer::add_options(boost::program_options::options_description& options)
{
    namespace po = boost::program_options;
    options.add_options()
        ("rpc-host", po::value<std::string>()->default_value("localhost"), "RPC host address")
        ("rpc-port", po::value<unsigned>()->default_value(23057), "RPC port number")
        ("rpc-radio-technology", po::value<std::string>()->default_value(""), "radio technology of RPC link layer (ITS-G5 | LTE-V2X)")
        ("rpc-debug", po::bool_switch()->default_value(false), "RPC debug output")
    ;
}
