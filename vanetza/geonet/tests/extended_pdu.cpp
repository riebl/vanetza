#include <vanetza/geonet/data_request.hpp>
#include <vanetza/geonet/mib.hpp>
#include <vanetza/geonet/packet.hpp>
#include <vanetza/geonet/parsed_pdu.hpp>
#include <vanetza/geonet/tests/network_topology.hpp>
#include <vanetza/geonet/tests/fake_interfaces.hpp>
#include <vanetza/net/mac_address.hpp>
#include <gtest/gtest.h>

using namespace vanetza;

class ExtendedPdu : public ::testing::Test
{
public:
    ExtendedPdu() : router(mib, req_ifc) {}

protected:
    virtual void SetUp() override
    {
        mib.itsGnSecurity = true;
        router.set_transport_handler(geonet::UpperProtocol::IPv6, ind_ifc);
    }

    std::unique_ptr<geonet::DownPacket> create_packet(ByteBuffer&& payload = {47, 11, 1, 4, 42, 85})
    {
        std::unique_ptr<geonet::DownPacket> packet { new geonet::DownPacket() };
        packet->layer(OsiLayer::Transport) = ByteBuffer(std::move(payload));
        return packet;
    }

    geonet::ManagementInformationBase mib;
    geonet::Router router;
    FakeRequestInterface req_ifc;
    FakeTransportInterface ind_ifc;
};

TEST_F(ExtendedPdu, shb_secured_header_serialization)
{
    geonet::ShbDataRequest request(mib, security::Profile::CAM);
    request.upper_protocol = geonet::UpperProtocol::IPv6;

    auto confirm = router.request(request, create_packet());
    EXPECT_TRUE(confirm.accepted());

    ByteBuffer net_payload;
    for (const auto layer : osi_layer_range<OsiLayer::Network, OsiLayer::Application>()) {
        ByteBuffer tmp;
        req_ifc.m_last_packet->layer(layer).convert(tmp);
        std::copy(tmp.begin(), tmp.end(), std::back_inserter(net_payload));
    }

    std::unique_ptr<geonet::UpPacket> packet_up { new geonet::UpPacket(CohesivePacket(net_payload, OsiLayer::Network)) };

    std::unique_ptr<geonet::ParsedPdu> dePdu = geonet::parse(*packet_up);

    ASSERT_NE(nullptr, dePdu);
    EXPECT_TRUE(dePdu->secured.is_initialized());
}
