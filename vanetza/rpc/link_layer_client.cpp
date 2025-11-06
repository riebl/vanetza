#include <vanetza/access/data_request.hpp>
#include <vanetza/access/pppp.hpp>
#include <vanetza/net/packet_variant.hpp>
#include <vanetza/rpc/link_layer_client.hpp>
#include <vanetza/rpc/logger.hpp>

#include <capnp/rpc-twoparty.h>
#include <capnp/rpc.h>
#include <kj/async.h>
#include <kj/time.h>
#include "vanetza.capnp.h"

#include <array>

namespace vanetza
{
namespace rpc
{

namespace
{

LinkLayerClient::ErrorCode map_error_code(vanetza::rpc::LinkLayer::ErrorCode in)
{
    switch (in)
    {
        case LinkLayer::ErrorCode::OK:
            return LinkLayerClient::ErrorCode::Ok;
        case LinkLayer::ErrorCode::INVALID_ARGUMENT:
            return LinkLayerClient::ErrorCode::InvalidArgument;
        case LinkLayer::ErrorCode::UNSUPPORTED:
            return LinkLayerClient::ErrorCode::Unsupported;
        case LinkLayer::ErrorCode::INTERNAL_ERROR:
        default:
            return LinkLayerClient::ErrorCode::InternalError;
    };
}

class DataListener : public vanetza::rpc::LinkLayer::DataListener::Server
{
public:
    DataListener(std::function<void(LinkLayerClient::Indication)> callback) :
        callback_(callback)
    {
    }

    kj::Promise<void> onDataIndication(OnDataIndicationContext context) override
    {
        auto frame = context.getParams().getFrame();
        vanetza::ByteBuffer payload { frame.getPayload().begin(), frame.getPayload().end() };
        LinkLayerClient::Indication indication { std::move(payload) };
        assign(indication.source, frame.getSourceAddress());
        assign(indication.destination, frame.getDestinationAddress());
        if (context.getParams().hasRxParams()) {
            if (context.getParams().getRxParams().isWlan()) {
                indication.technology = LinkLayerClient::Technology::ITS_G5;
            } else if (context.getParams().getRxParams().isCv2x()) {
                indication.technology = LinkLayerClient::Technology::LTE_V2X;  
            }
        }
        callback_(std::move(indication));
        return kj::READY_NOW;
    }

    void assign(MacAddress& into, const capnp::Data::Reader& from)
    {
        if (from.size() == MacAddress::length_bytes)
        {
            std::copy(from.begin(), from.end(), into.octets.begin());
        }
        else if (from.size() < MacAddress::length_bytes)
        {
            auto it = std::next(into.octets.begin(), MacAddress::length_bytes - from.size());
            std::fill(into.octets.begin(), it, 0);
            std::copy(from.begin(), from.end(), it);
        }
        else
        {
            auto it = std::next(from.begin(), from.size() - MacAddress::length_bytes);
            std::copy(it, from.end(), into.octets.begin());
        }
    }

private:
    std::function<void(LinkLayerClient::Indication)> callback_;
};

class CbrListener : public vanetza::rpc::LinkLayer::CbrListener::Server
{
public:
    CbrListener(std::function<void(dcc::ChannelLoad)> callback) :
        callback_(callback)
    {
    }

    kj::Promise<void> onCbrReport(OnCbrReportContext context) override
    {
        auto cbr = context.getParams().getCbr();
        dcc::ChannelLoad channel_load;
        if (cbr.getSamples() > 0 && cbr.getBusy() > 0) {
            if (cbr.getSamples() >= cbr.getBusy()) {
                channel_load = dcc::ChannelLoad(cbr.getBusy(), cbr.getSamples());
            } else {
                channel_load = dcc::ChannelLoad(cbr.getSamples(), cbr.getSamples());
            }
        };
        callback_(channel_load);
        return kj::READY_NOW;
    }

private:
    std::function<void(dcc::ChannelLoad)> callback_;
};

} // namespace

LinkLayerClient::Indication::Indication(vanetza::ByteBuffer buffer) :
    packet(std::move(buffer), OsiLayer::Network)
{
}

class LinkLayerClient::Context : public kj::TaskSet::ErrorHandler
{
public:
    Context(kj::Timer& timer, kj::AsyncIoStream& connection, Logger* logger) :
        logger_(logger),
        timer_(timer),
        task_set_(*this),
        client_(connection),
        link_layer_(client_.bootstrap().castAs<vanetza::rpc::LinkLayer>())
    {
    }

    void taskFailed(kj::Exception&& exception) override
    {
        VANETZA_RPC_LOG_ERROR(logger_, "LinkLayerClient/task", exception.getDescription().cStr());
    }

    void addTask(kj::Promise<void>&& promise, kj::Duration timeout)
    {
        task_set_.add(timer_.timeoutAfter(timeout, kj::mv(promise)));
    }

    Logger* logger_ = nullptr;
    kj::Timer& timer_;
    kj::TaskSet task_set_;
    capnp::TwoPartyClient client_;
    vanetza::rpc::LinkLayer::Client link_layer_;
};

LinkLayerClient::LinkLayerClient(kj::Timer& timer, kj::AsyncIoStream& connection, Logger* logger) :
    context_(std::make_unique<Context>(timer, connection, logger))
{
    auto rx_data = context_->link_layer_.subscribeDataRequest();
    rx_data.setListener(kj::heap<DataListener>(std::bind(&LinkLayerClient::do_indicate, this, std::placeholders::_1)));
    context_->addTask(rx_data.send().ignoreResult(), 1 * kj::SECONDS);

    auto cbr = context_->link_layer_.subscribeCbrRequest();
    cbr.setListener(kj::heap<CbrListener>(std::bind(&LinkLayerClient::do_report, this, std::placeholders::_1)));
    context_->addTask(cbr.send().ignoreResult(), 1 * kj::SECONDS);
}

LinkLayerClient::~LinkLayerClient()
{
}

void LinkLayerClient::configure(Technology technology)
{
    VANETZA_RPC_LOG_DEBUG(context_->logger_, "LinkLayerClient/configure", stringify(technology));
    technology_ = technology;
}

void LinkLayerClient::add_task(kj::Promise<void>&& promise)
{
    VANETZA_RPC_LOG_DEBUG(context_->logger_, "LinkLayerClient/task", "add");
    context_->task_set_.add(kj::mv(promise));
}

kj::Promise<LinkLayerClient::Identity> LinkLayerClient::identify()
{
    auto ident_request = context_->link_layer_.identifyRequest();
    auto promise = ident_request.send().then(
    [](capnp::Response<rpc::LinkLayer::IdentifyResults>&& results) mutable -> kj::Promise<Identity> {
              Identity identity;
              identity.id = results.getId();
              identity.version = results.getVersion();
              if (results.hasInfo()) {
                identity.info = results.getInfo().cStr();
              }
              return identity;
          });
    return promise;
}

void LinkLayerClient::request(const access::DataRequest& request, std::unique_ptr<ChunkPacket> packet)
{
    auto tx_data = context_->link_layer_.transmitDataRequest();

    auto frame = tx_data.initFrame();
    frame.setSourceAddress(kj::ArrayPtr<const kj::byte> { request.source_addr.octets.data(), request.source_addr.octets.size() });
    frame.setDestinationAddress(kj::ArrayPtr<const kj::byte> { request.destination_addr.octets.data(), request.destination_addr.octets.size() });
    auto payload_view = create_byte_view(*packet, OsiLayer::Network, OsiLayer::Application);
    vanetza::ByteBuffer payload { payload_view.begin(), payload_view.end() };
    frame.setPayload(kj::ArrayPtr<const kj::byte> { payload.data(), payload.size() });

    auto tx_params = tx_data.initTxParams();
    if (technology_ == Technology::ITS_G5) {
        auto wlan_tx_params = tx_params.initWlan();
        wlan_tx_params.setPriority(access::user_priority(request.access_category));
    } else if (technology_ == Technology::LTE_V2X) {
        auto cv2x_tx_params = tx_params.initCv2x();
        cv2x_tx_params.setPriority(access::pppp_from_ac(request.access_category));
    }

    auto promise = tx_data.send().then([this](capnp::Response<vanetza::rpc::LinkLayer::TransmitDataResults>&& results) -> kj::Promise<void> {
        if (results.getError() != vanetza::rpc::LinkLayer::ErrorCode::OK) {
            VANETZA_RPC_LOG_ERROR(context_->logger_, "LinkLayerClient/request", stringify(map_error_code(results.getError())));
        } else {
            VANETZA_RPC_LOG_DEBUG(context_->logger_, "LinkLayerClient/request", "ok");
        }
        return kj::READY_NOW;
    });
    context_->addTask(kj::mv(promise), 100 * kj::MILLISECONDS);
}

void LinkLayerClient::do_indicate(Indication indication)
{
    VANETZA_RPC_LOG_DEBUG(context_->logger_, "LinkLayerClient/indicate", stringify(indication.technology))
    std::lock_guard<std::mutex> lock(callback_mutex_);
    if (indication_callback_) {
        indication_callback_(indication);
    }
}

void LinkLayerClient::do_report(dcc::ChannelLoad cl)
{
    std::lock_guard<std::mutex> lock(callback_mutex_);
    if (cbr_callback_) {
        cbr_callback_(cl);
    }
}

void LinkLayerClient::indicate(IndicationCallback callback)
{
    std::lock_guard<std::mutex> lock(callback_mutex_);
    indication_callback_ = callback;
}

void LinkLayerClient::report_channel_load(ChannelLoadReportCallback callback)
{
    std::lock_guard<std::mutex> lock(callback_mutex_);
    cbr_callback_ = callback;
}

kj::Promise<LinkLayerClient::ErrorCode> LinkLayerClient::set_source_address(const MacAddress& addr)
{
    auto request = context_->link_layer_.setSourceAddressRequest();
    auto msg_addr = request.initAddress(MacAddress::length_bytes);
    std::copy(addr.octets.begin(), addr.octets.end(), msg_addr.begin());

    using Response = capnp::Response<vanetza::rpc::LinkLayer::SetSourceAddressResults>;
    kj::ForkedPromise<ErrorCode> forked = request.send().then([this](Response&& response) -> kj::Promise<ErrorCode> {
        auto result = map_error_code(response.getError());
        VANETZA_RPC_LOG_DEBUG(context_->logger_, "LinkLayerClient/SetSourceAddress", stringify(result));
        return result;
    }).fork();
    context_->addTask(forked.addBranch().ignoreResult(), 500 * kj::MILLISECONDS);
    return forked.addBranch();
}

const char* stringify(LinkLayerClient::ErrorCode ec)
{
    using ErrorCode = LinkLayerClient::ErrorCode;
    static const std::array<const char*, 4> strings = { "ok", "invalid argument", "unsupported", "internal error" };
    static_assert(static_cast<std::size_t>(ErrorCode::Ok) == 0, "ErrorCode 'ok' is at index 0");
    const auto idx = static_cast<std::size_t>(ec);
    if (idx >= strings.size()) {
        return "unknown";
    } else {
        return strings[idx]; 
    }
}

const char* stringify(LinkLayerClient::Technology tech)
{
    using Tech = LinkLayerClient::Technology;
    if (tech == Tech::ITS_G5) {
        return "ITS-G5";
    } else if (tech == Tech::LTE_V2X) {
        return "LTE-V2X";
    } else if (tech == Tech::Unspecified) {
        return "unspecified";
    } else {
        return "unknown";
    }
}

} // namespace rpc
} // namespace vanetza
