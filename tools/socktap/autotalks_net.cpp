#include "autotalks_net.hpp"

#include <capnp/rpc.h>
#include <capnp/rpc-twoparty.h>
#include <vanetza/access/g5_link_layer.hpp>
#include <vanetza/common/serialization_buffer.hpp>
#include <vanetza/access/ethertype.hpp>

#include <boost/asio.hpp>
#include <cstdio>
#include <iostream>


namespace vanetza
{
namespace autotalks_net
{


AutotalksNet::AutotalksNet(V2XOperationMode_t mode, boost::asio::io_service& io, const std::string& endpoint)
                           : mode_(mode),
                             boostIoContext(io),
                             disconnected_(false),
                             paf_(nullptr)
{
    rpcThread_ = std::thread(&AutotalksNet::rpcThreadMain, this, endpoint);
}

AutotalksNet::~AutotalksNet(void)
{
    if (exitCallback_)
    {
        exitCallback_(paf_.load());
    }
    rpcThread_.join();
}

vanetza::MacAddress numVecL2IdToMac(const std::vector<uint8_t>& data)
{
    vanetza::MacAddress ret;
    for (size_t i = 3; i < data.size(); i++)
    {
        ret.octets[i] = data[i];
    }
    return ret;
}

vanetza::MacAddress numVecToMac(std::vector<uint8_t> data)
{
    vanetza::MacAddress ret;
    for (size_t i = 0; i < data.size(); i++)
    {
        ret.octets[i] = data[i];
    }
    return ret;
}

void AutotalksNet::Transmit(const vanetza::access::DataRequest& request, uint8_t* pData,
                            uint16_t length, vanetza::geonet::InterfaceType interface)
{
    // RPC version
    if (rpcTransmit_ && !disconnected_)
    {
        rpcTransmit_(request, pData, length, interface);
    }
}

void AutotalksNet::SetMac(const std::vector<uint8_t>& addr)
{
    if (rpcMacTransmit_ && !disconnected_)
    {
        rpcMacTransmit_(addr);
    }
}

void AutotalksNet::Indicate(std::function<void(const V2xFrame&)> callback)
{
    packetRxCallback_ = callback;
}

void AutotalksNet::IndicateDcc(std::function<void(const ChannelBusyRatio&)> callback)
{
    packetCbrRxCallback_ = callback;
}

void AutotalksNet::IndicateAddressChange(std::function<void(const vanetza::MacAddress& address)> callback)
{
    addressChangeCallback_ = callback;
}

boost::optional<vanetza::EthernetHeader> AutotalksNet::strip_rx_header(vanetza::CohesivePacket& packet,
                                                                       const V2xFrame& frame)
{
    vanetza::access::G5LinkLayer link_layer;
    vanetza::ByteBuffer link_layer_buffer;
    link_layer.mac_header.destination = numVecToMac(frame.DstAddress);
    link_layer.mac_header.source = numVecToMac(frame.SrcAddress);
    link_layer.llc_snap_header.protocol_id = vanetza::access::ethertype::GeoNetworking;
    vanetza::serialize_into_buffer(link_layer, link_layer_buffer);
    assert(link_layer_buffer.size() == vanetza::access::G5LinkLayer::length_bytes);

    vanetza::ByteBuffer finalBuffer;
    for (auto i : link_layer_buffer)
    {
        finalBuffer.push_back(i);
    }
    for (uint16_t i = 0; i < frame.Data.size(); i++)
    {
        finalBuffer.push_back(frame.Data[i]);
    }

    vanetza::CohesivePacket finalPkt(finalBuffer, vanetza::OsiLayer::Physical);
    finalPkt.set_boundary(vanetza::OsiLayer::Physical, 0);
    finalPkt.set_boundary(vanetza::OsiLayer::Link, vanetza::access::G5LinkLayer::length_bytes);
    finalPkt.set_boundary(vanetza::OsiLayer::Network, packet.size());
    packet = finalPkt;

    vanetza::EthernetHeader eth;
    if (mode_ == V2XOperationMode_t::ITS_G5)
    {
        eth.destination = numVecToMac(frame.DstAddress);
        eth.source = numVecToMac(frame.SrcAddress);
    }
    else
    {
        eth.destination = numVecL2IdToMac(frame.DstAddress);
        eth.source = numVecL2IdToMac(frame.SrcAddress);
    }
    eth.type = vanetza::access::ethertype::GeoNetworking; // This is the same as in protocol_id in socket parameters
    return eth;
}

void AutotalksNet::rpcThreadMain(const std::string& endpoint)
{
    auto io = kj::setupAsyncIo();
    auto& waitScope = io.waitScope;
    kj::Own<kj::NetworkAddress> addr;
    kj::Network& network = io.provider->getNetwork();
    try {
        addr = network.parseAddress(endpoint).wait(waitScope);
    } catch (const kj::Exception& e) {
        KJ_LOG(ERROR, "Address parsing error", e);
        return;
    }

    kj::Own<kj::AsyncIoStream> conn;
    try {
        conn = addr->connect().wait(waitScope);
    } catch (const kj::Exception& e) {
        KJ_LOG(ERROR, "Connection error", e);
        return;
    }
    kj::PromiseFulfillerPair<void> paf = kj::newPromiseAndFulfiller<void>();
    paf_.store(&paf);

    capnp::TwoPartyClient rpcClient(*conn);
    vanetza::rpc::LinkLayer::Client linkLayerClient = rpcClient.bootstrap().castAs<vanetza::rpc::LinkLayer>();
    kj::Own<LinkLayerImpl> linkLayerImpl(kj::heap<LinkLayerImpl>(linkLayerClient, this));
    kj::Own<DataListenerImpl> dataListenerImpl(kj::heap<DataListenerImpl>(boostIoContext, this));
    kj::Own<CbrListenerImpl> cbrListenerImpl(kj::heap<CbrListenerImpl>(boostIoContext, this));

    auto subscribeRequest = linkLayerClient.subscribeDataRequest();
    subscribeRequest.setListener(kj::mv(dataListenerImpl));
    try {
        subscribeRequest.send()
            .catch_([](kj::Exception&& e) -> kj::Promise<capnp::Response<vanetza::rpc::LinkLayer::SubscribeDataResults>> {
                std::cerr << "Subscription failed: " << e.getDescription().cStr() << std::endl;
                return kj::Promise<capnp::Response<vanetza::rpc::LinkLayer::SubscribeDataResults>>(std::move(e));
            })
            .wait(waitScope);
    } catch (const kj::Exception& e) {
        KJ_LOG(ERROR, "Subscription failed", e);
        return;
    }
    auto subscribeCbrRequest = linkLayerClient.subscribeCbrRequest();
    subscribeCbrRequest.setListener(kj::mv(cbrListenerImpl));
    try {
        subscribeCbrRequest.send()
            .catch_([](kj::Exception&& e) -> kj::Promise<capnp::Response<vanetza::rpc::LinkLayer::SubscribeCbrResults>> {
                std::cerr << "CBR subscription failed: " << e.getDescription().cStr() << std::endl;
                return kj::Promise<capnp::Response<vanetza::rpc::LinkLayer::SubscribeCbrResults>>(std::move(e));
            })
            .wait(waitScope);
    } catch (const kj::Exception& e) {
        KJ_LOG(ERROR, "CBR subscription failed", e);
        return;
    }

    auto shutdownHandler = [this]() {
        std::cout << "Client was disconnected / end was requested" << std::endl;
        disconnected_ = true;
    };

    auto disconnectPromise = rpcClient.onDisconnect().then(shutdownHandler);
    disconnectPromise.exclusiveJoin(paf.promise.then(shutdownHandler)).wait(waitScope);

    paf_.store(nullptr);
    rpcTransmit_ = nullptr;
    exitCallback_ = nullptr;
}

void AutotalksNet::SetNetRequest(std::function<void(const vanetza::access::DataRequest&, uint8_t*, uint16_t, vanetza::geonet::InterfaceType)> callback)
{
    rpcTransmit_ = callback;
}

void AutotalksNet::SetNetMacRequest(std::function<void(const std::vector<uint8_t>& address)> callback)
{
    rpcMacTransmit_ = callback;
}

void AutotalksNet::SetExitCallback(std::function<void(kj::PromiseFulfillerPair<void>* pPaf)> callback)
{
    exitCallback_ = callback;
}

void AutotalksNet::PacketReception(const V2xFrame& frame)
{
    if (packetRxCallback_)
    {
        packetRxCallback_(frame);
    }
}

void AutotalksNet::CbrReception(const ChannelBusyRatio& cbr)
{
    if (packetCbrRxCallback_)
    {
        packetCbrRxCallback_(cbr);
    }
}

void AutotalksNet::AddressChanged(const vanetza::MacAddress& address)
{
    if (addressChangeCallback_)
    {
        addressChangeCallback_(address);
    }
}

LinkLayerImpl::LinkLayerImpl(vanetza::rpc::LinkLayer::Client& client, AutotalksNet* pNet)
                             : linkLayerClient_(client),
                               executor_(kj::getCurrentThreadExecutor()),
                               net_(pNet)
{
    pNet->SetNetRequest(std::bind(&LinkLayerImpl::Transmit, this, std::placeholders::_1,
                                  std::placeholders::_2, std::placeholders::_3, std::placeholders::_4));
    pNet->SetNetMacRequest(std::bind(&LinkLayerImpl::TransmitMacChange, this, std::placeholders::_1));
    pNet->SetExitCallback(std::bind(&LinkLayerImpl::Exit, this, std::placeholders::_1));

    Identify();
}

LinkLayerImpl::~LinkLayerImpl(void)
{
    net_->SetNetRequest(nullptr);
    net_->SetNetMacRequest(nullptr);
}

void LinkLayerImpl::Transmit(const vanetza::access::DataRequest& request, uint8_t* pData,
                             uint16_t length, vanetza::geonet::InterfaceType interface)
{
    if (executor_.isLive()) {
        executor_.executeSync([this, request, pData, length, interface]() {
            try {
                auto transmitRequest = linkLayerClient_.transmitDataRequest();
                auto frame = transmitRequest.initFrame();

                frame.setSourceAddress(kj::heapArray<const capnp::byte>(request.source_addr.octets.data(),
                                                                        request.source_addr.octets.size()));
                frame.setDestinationAddress(kj::heapArray<const capnp::byte>(request.destination_addr.octets.data(),
                                                                             request.destination_addr.octets.size()));
                frame.setPayload(kj::heapArray(pData, length));

                auto params = transmitRequest.initTxParams();
                if (vanetza::geonet::InterfaceType::ITS_G5 == interface)
                {
                    auto wlanParams = params.initWlan();
                    wlanParams.setPriority((uint8_t) request.access_category);
                    wlanParams.setPower(V2X_TX_POWER);
                    wlanParams.setDatarate(V2X_TX_DATARATE_DEFAULT);
                }
                else if (vanetza::geonet::InterfaceType::LTE_V2X == interface)
                {
                    auto cv2xParams = params.initCv2x();
                    cv2xParams.setPriority((uint8_t) request.access_category);
                    cv2xParams.setPower(V2X_TX_POWER);
                }
                else
                {
                    params.setUnspecified();
                }
                transmitRequest.send().then([this](capnp::Response<vanetza::rpc::LinkLayer::TransmitDataResults> result) mutable {
                    auto error = result.getError();
                    auto message = result.getMessage();
                    printf("Sent Data Indication. Response: %s (%s)\n", kj::str(error).cStr(), message.cStr());

                })
                .catch_([this](kj::Exception&& e) -> kj::Promise<void> {
                    if (e.getType() == kj::Exception::Type::DISCONNECTED) {
                        KJ_DBG("[CLIENT] Client was disconnected.");
                    } else {
                        KJ_LOG(ERROR, "request.send() exception", e);
                    }
                    return kj::READY_NOW;
                }).eagerlyEvaluate([](kj::Exception&& exception) {
                    KJ_LOG(ERROR, exception);
                }).detach([this](kj::Exception&& e) {
                    KJ_LOG(ERROR, "Sending exception", e);
                });
            } catch (const kj::Exception& e) {
                std::cerr << "Caught kj::Exception during transmit: " << e.getDescription().cStr() << std::endl;
            }
        });
    }
}

void LinkLayerImpl::TransmitMacChange(const std::vector<uint8_t>& address)
{
    if (executor_.isLive()) {
        executor_.executeSync([address, this]() {
            try {
                auto transmitRequest = linkLayerClient_.setSourceAddressRequest();
                transmitRequest.setAddress(kj::heapArray<capnp::byte>(address.data(), address.size()));

                transmitRequest.send().then([address, this](capnp::Response<vanetza::rpc::LinkLayer::SetSourceAddressResults> result) mutable {
                    auto error = result.getError();
                    // Set the MAC address
                    std::cout << "Setting MAC address: " << (int) address[0] << ", " << (int) address[1] << ", " << (int) address[2]
                                                         << ", " << (int) address[3] << ", " << (int) address[4] << ", " << (int) address[5] << std::endl;
                    printf("MAC address set Indication. Response: %s\n", kj::str(error).cStr());
                    vanetza::MacAddress mac({address[0], address[1], address[2], address[3], address[4], address[5]});
                    if (net_)
                    {
                        net_->AddressChanged(mac);
                    }
                })
                .catch_([this](kj::Exception&& e) -> kj::Promise<void> {
                    if (e.getType() == kj::Exception::Type::DISCONNECTED) {
                        KJ_DBG("[CLIENT] Client was disconnected.");
                    } else {
                        KJ_LOG(ERROR, "request.send() exception", e);
                    }
                    return kj::READY_NOW;
                }).eagerlyEvaluate([](kj::Exception&& exception) {
                    KJ_LOG(ERROR, exception);
                }).detach([this](kj::Exception&& e) {
                    KJ_LOG(ERROR, "Sending exception", e);
                });
            } catch (const kj::Exception& e) {
                std::cerr << "Caught kj::Exception during transmit: " << e.getDescription().cStr() << std::endl;
            }
        });
    }
}

void LinkLayerImpl::Identify(void)
{
    // This does not use the executor as of right now, this is done directly in the constructor
    auto identifyRequest = linkLayerClient_.identifyRequest();
    identifyRequest.send().then([this](capnp::Response<vanetza::rpc::LinkLayer::IdentifyResults> result) mutable {
        uint64_t id = result.getId();
        uint32_t version = result.getVersion();
        auto info = result.getInfo();
        printf("ID: %" PRIu64 ", version: %" PRIu32 ", info: %s\n", id, version, info.cStr());
    })
    .catch_([this](kj::Exception&& e) -> kj::Promise<void> {
        if (e.getType() == kj::Exception::Type::DISCONNECTED) {
            KJ_DBG("[CLIENT] Client was disconnected.");
        } else {
            KJ_LOG(ERROR, "request.send() exception", e);
        }
        return kj::READY_NOW;
    }).eagerlyEvaluate([](kj::Exception&& exception) {
        KJ_LOG(ERROR, exception);
    }).detach([this](kj::Exception&& e) {
        KJ_LOG(ERROR, "Sending exception", e);
    });
}

void LinkLayerImpl::Exit(kj::PromiseFulfillerPair<void>* pPaf)
{
    executor_.executeSync([pPaf, this]() mutable {
        if (nullptr != pPaf)
        {
            pPaf->fulfiller->fulfill();
        }
    });
}

DataListenerImpl::DataListenerImpl(boost::asio::io_context& io_context, AutotalksNet* pNet)
                                   : io_context_(io_context),
                                     executor_(kj::getCurrentThreadExecutor()),
                                     net_(pNet)
{
}

kj::Promise<void> DataListenerImpl::onDataIndication(OnDataIndicationContext context)
{
    V2xFrame v2xFrame;

    auto frame = context.getParams().getFrame();
    auto params = context.getParams().getRxParams();

    auto source = frame.getSourceAddress();
    auto destination = frame.getDestinationAddress();
    auto payload = frame.getPayload();
    auto timestamp = params.getTimestamp();

    printf("Received Data Indication:\n");
    if (vanetza::rpc::LinkLayer::RxParameters::Timestamp::HARDWARE == timestamp.which())
    {
        printf("  Timestamp: %" PRIu64 " (hardware)\n", timestamp.getHardware());
    }
    else if (vanetza::rpc::LinkLayer::RxParameters::Timestamp::SOFTWARE == timestamp.which())
    {
        printf("  Timestamp: %" PRIu64 " (software)\n", timestamp.getHardware());
    }
    else    // vanetza::rpc::LinkLayer::RxParameters::Timestamp::NONE == timestamp.which()
    {
        printf("  Timestamp: invalid\n");
    }
    printf("  Source Address: ");
    for (auto byte : source) {
        printf("%02X ", byte);
        v2xFrame.SrcAddress.push_back(byte);
    }
    printf("\n  Destination Address: ");
    for (auto byte : destination) {
        printf("%02X ", byte);
        v2xFrame.DstAddress.push_back(byte);
    }
    printf("\n  Payload: ");
    for (auto byte : payload) {
        printf("%02X", byte);
        v2xFrame.Data.push_back(byte);
    }

    (void) printf("\n  Parameters:  ");
    if (vanetza::rpc::LinkLayer::RxParameters::WLAN == params.which())
    {
        v2xFrame.WlanParameters.Datarate = params.getWlan().getDatarate();
        v2xFrame.WlanParameters.Power = params.getWlan().getPower();
        v2xFrame.WlanParameters.Priority = params.getWlan().getPriority();
        (void) printf("datarate: %u, power: %d, priority: %d", v2xFrame.WlanParameters.Datarate,
                                                               v2xFrame.WlanParameters.Power,
                                                               v2xFrame.WlanParameters.Priority);
    }
    else if (vanetza::rpc::LinkLayer::RxParameters::CV2X == params.which())
    {
        v2xFrame.Cv2xParameters.Power = params.getWlan().getPower();
        v2xFrame.Cv2xParameters.Priority = params.getWlan().getPriority();
        (void) printf("power: %d, priority: %d", v2xFrame.Cv2xParameters.Power,
                                                 v2xFrame.Cv2xParameters.Priority);
    }
    else
    {
        (void) printf("invalid");
    }
    printf("\n");

    io_context_.post([v2xFrame, this] {
        if (net_)
        {
            net_->PacketReception(v2xFrame);
        }
        std::cout << "Data indication received (via io_context)" << std::endl;
        // Further processing within boost::asio context
    });

    return kj::READY_NOW;
}

CbrListenerImpl::CbrListenerImpl(boost::asio::io_context& io_context, AutotalksNet* pNet)
                                   : io_context_(io_context),
                                     executor_(kj::getCurrentThreadExecutor()),
                                     net_(pNet)
{
}

kj::Promise<void> CbrListenerImpl::onCbrReport(OnCbrReportContext context)
{
    auto cbr = context.getParams().getCbr().getBusy();
    auto samples = context.getParams().getCbr().getSamples();
    ChannelBusyRatio channelBusyRatio = {.Busy = cbr, .Samples = samples};

    io_context_.post([channelBusyRatio, this] {
        // Further processing within boost::asio context
        if (net_)
        {
            net_->CbrReception(channelBusyRatio);
        }
    });
    return kj::READY_NOW;
}


}   // namespace vanetza
}   // namespace autotalks_net
