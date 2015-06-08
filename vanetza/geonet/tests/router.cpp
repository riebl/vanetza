#include <gtest/gtest.h>
#include <vanetza/dcc/data_request.hpp>
#include <vanetza/dcc/interface.hpp>
#include <vanetza/geonet/data_confirm.hpp>
#include <vanetza/geonet/data_indication.hpp>
#include <vanetza/geonet/mib.hpp>
#include <vanetza/geonet/router.hpp>
#include <vanetza/geonet/transport_interface.hpp>
#include <boost/optional.hpp>

using namespace vanetza;
using namespace vanetza::geonet;

class FakeRequestInterface : public dcc::RequestInterface
{
public:
    FakeRequestInterface() : m_requests(0) {}

    void request(const dcc::DataRequest& req, std::unique_ptr<ChunkPacket> packet) override
    {
        ++m_requests;
        m_last_request = req;
        m_last_packet = std::move(packet);
    }

    unsigned m_requests;
    dcc::DataRequest m_last_request;
    std::unique_ptr<ChunkPacket> m_last_packet;
};

class FakeTransportInterface : public TransportInterface
{
public:
    FakeTransportInterface() : m_indications(0) {}

    void indicate(const DataIndication& ind, std::unique_ptr<UpPacket> packet) override
    {
        ++m_indications;
        m_last_indication = ind;
        m_last_packet = std::move(packet);
    }

    unsigned m_indications;
    boost::optional<DataIndication> m_last_indication;
    std::unique_ptr<UpPacket> m_last_packet;
};

TEST(Router, shb_round_trip)
{
    FakeRequestInterface req_ifc;
    FakeTransportInterface ind_ifc;
    ManagementInformationBase mib;
    const ByteBuffer send_payload { 89, 27, 1, 4, 18, 85 };

    Router router(mib, req_ifc);
    router.set_transport_handler(UpperProtocol::IPv6, ind_ifc);

    ShbDataRequest shb_request(mib);
    shb_request.upper_protocol = UpperProtocol::IPv6;
    std::unique_ptr<DownPacket> packet_down { new DownPacket() };
    packet_down->layer(OsiLayer::Transport) = ByteBuffer(send_payload);
    const auto requests_before = req_ifc.m_requests;
    auto confirm = router.request(shb_request, std::move(packet_down));
    ASSERT_TRUE(confirm.accepted());
    EXPECT_EQ(requests_before + 1, req_ifc.m_requests);

    ASSERT_TRUE(req_ifc.m_last_packet.get() != nullptr);
    ByteBuffer net_payload;
    for (const auto layer : osi_layer_range<OsiLayer::Network, OsiLayer::Application>()) {
        ByteBuffer tmp;
        req_ifc.m_last_packet->layer(layer).convert(tmp);
        std::copy(tmp.begin(), tmp.end(), std::back_inserter(net_payload));
    }
    ASSERT_EQ(req_ifc.m_last_packet->size(OsiLayer::Network, OsiLayer::Application), net_payload.size());
    std::unique_ptr<UpPacket> packet_up { new UpPacket(CohesivePacket(net_payload, OsiLayer::Network)) };
    ASSERT_EQ(
            size(*req_ifc.m_last_packet, min_osi_layer(), max_osi_layer()),
            size(*packet_up, OsiLayer::Network)
        );

    const auto indications_before = ind_ifc.m_indications;
    router.indicate(std::move(packet_up), {1, 2, 3, 4, 5, 6}, cBroadcastMacAddress);
    EXPECT_EQ(indications_before + 1, ind_ifc.m_indications);

    ASSERT_NE(nullptr, ind_ifc.m_last_packet.get());
    CohesivePacket* received_payload_ptr = boost::get<CohesivePacket>(ind_ifc.m_last_packet.get());
    ASSERT_NE(nullptr, received_payload_ptr);
    auto received_payload_range = (*received_payload_ptr)[OsiLayer::Transport];
    const ByteBuffer received_payload = ByteBuffer {
        received_payload_range.begin(), received_payload_range.end()
    };
    EXPECT_EQ(send_payload, received_payload);
}
