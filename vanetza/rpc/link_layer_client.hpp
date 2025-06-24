#pragma once
#include <kj/async-io.h>
#include <vanetza/dcc/channel_load.hpp>
#include <vanetza/net/chunk_packet.hpp>
#include <vanetza/net/cohesive_packet.hpp>
#include <vanetza/net/mac_address.hpp>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <string>

namespace vanetza
{

namespace access { class DataRequest; }

namespace rpc
{

class Logger;

class LinkLayerClient
{
public:
    enum class ErrorCode
    {
        Ok,
        InvalidArgument,
        Unsupported,
        InternalError,
    };

    enum class Technology
    {
        Unspecified,
        ITS_G5,
        LTE_V2X,
    };

    struct Indication
    {
        Indication(vanetza::ByteBuffer);

        vanetza::MacAddress source;
        vanetza::MacAddress destination;
        vanetza::CohesivePacket packet;
        Technology technology = Technology::Unspecified;
    };

    struct Identity
    {
        std::uint64_t id = 0;
        std::uint32_t version = 0;
        std::string info;
    };

    using IndicationCallback = std::function<void(Indication)>;
    using ChannelLoadReportCallback = std::function<void(dcc::ChannelLoad)>;

    LinkLayerClient(kj::Timer&, kj::AsyncIoStream&, Logger* = nullptr);
    ~LinkLayerClient();

    kj::Promise<Identity> identify();
    void request(const access::DataRequest&, std::unique_ptr<ChunkPacket>);
    void indicate(IndicationCallback callback);
    void report_channel_load(ChannelLoadReportCallback callback);
    kj::Promise<ErrorCode> set_source_address(const MacAddress&);

    void configure(Technology);
    void add_task(kj::Promise<void>&&);

private:
    class Context;

    void do_indicate(Indication);
    void do_report(dcc::ChannelLoad);

    std::unique_ptr<Context> context_;
    std::mutex callback_mutex_;
    IndicationCallback indication_callback_;
    ChannelLoadReportCallback cbr_callback_;
    Technology technology_ = Technology::Unspecified;
};

const char* stringify(LinkLayerClient::ErrorCode);
const char* stringify(LinkLayerClient::Technology);

} // namespace rpc
} // namespace vanetza
