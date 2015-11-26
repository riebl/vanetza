#include <gtest/gtest.h>
#include <vanetza/geonet/tests/fake_interfaces.hpp>
#include <vanetza/geonet/pdu_conversion.hpp>
#include <vanetza/geonet/pdu_variant.hpp>
#include <vanetza/geonet/router.hpp>
#include <vanetza/geonet/serialization_buffer.hpp>

using namespace vanetza;
using namespace vanetza::geonet;

class RouterRequest : public ::testing::Test
{
public:
    RouterRequest() : router(mib, req_ifc) {}

protected:
    virtual void SetUp() override
    {
        mib.itsGnSecurity = true;
        router.set_transport_handler(geonet::UpperProtocol::IPv6, ind_ifc);
        test_payload = {47, 11, 1, 4, 42, 85};
    }

    std::unique_ptr<geonet::DownPacket> create_packet()
    {
        std::unique_ptr<DownPacket> packet { new DownPacket() };
        packet->layer(OsiLayer::Transport) = ByteBuffer(test_payload);
        return packet;
    }

    ManagementInformationBase mib;
    Router router;
    FakeRequestInterface req_ifc;
    FakeTransportInterface ind_ifc;
    ByteBuffer test_payload;
};

TEST_F(RouterRequest, router_request)
{
    // create ShbDataRequest
    ShbDataRequest request(mib, security::Profile::CAM);
    request.upper_protocol = UpperProtocol::IPv6;

    // Router handles request
    auto confirm = router.request(request, create_packet());
    EXPECT_TRUE(confirm.accepted());

    // get the data from the fake network
    ByteBuffer net_payload;
    for (const auto layer : osi_layer_range<OsiLayer::Network, OsiLayer::Application>()) {
        ByteBuffer tmp;
        req_ifc.m_last_packet->layer(layer).convert(tmp);
        std::copy(tmp.begin(), tmp.end(), std::back_inserter(net_payload));
    }

    UpPacket packet_up { CohesivePacket(net_payload, OsiLayer::Network) };

    DownPacket packet_mac = *req_ifc.m_last_packet;
    // all data should be in network layer: payload is encapsulated by secured message
    EXPECT_EQ(packet_mac.size(), packet_mac[OsiLayer::Network].size());

    // prepare access to network layer's PDU
    using pdu_convertible = convertible::byte_buffer_impl<std::unique_ptr<Pdu>>;
    pdu_convertible* pdu_conv = dynamic_cast<pdu_convertible*>(packet_mac[OsiLayer::Network].ptr());
    ASSERT_TRUE(pdu_conv);
    auto pdu = pdu_conv->m_pdu.get();
    ASSERT_TRUE(pdu);
    auto pdu_ext = dynamic_cast<ShbPdu*>(pdu);
    ASSERT_TRUE(pdu_ext);

    // check if packet has secured part
    EXPECT_EQ(NextHeaderBasic::SECURED, pdu->basic().next_header);
    EXPECT_TRUE(pdu_ext->secured());
    auto secured = *pdu_ext->secured();

    // check payload of packet
    EXPECT_EQ(security::PayloadType::Signed, secured.payload.type);
    EXPECT_EQ(test_payload.size(), pdu->common().payload);
    const size_t payload_header_length = CommonHeader::length_bytes + ShbHeader::length_bytes;
    EXPECT_EQ(test_payload.size() + payload_header_length, secured.payload.buffer.size());
    ByteBuffer payload {
        secured.payload.buffer.begin() + payload_header_length,
        secured.payload.buffer.end()
    };
    EXPECT_EQ(test_payload, payload);
    ByteBuffer payload_header;
    serialize_into_buffer(pdu_ext->common(), payload_header);
    serialize_into_buffer(pdu_ext->extended(), payload_header);
    EXPECT_EQ(payload_header_length, payload_header.size());
    secured.payload.buffer.resize(payload_header_length);
    EXPECT_EQ(payload_header, secured.payload.buffer);
}

TEST_F(RouterRequest, modified_request_maximum_lifetime)
{
    // create ShbDataRequest
    ShbDataRequest request(mib, security::Profile::CAM);

    // create new Lifetime that is larger than the itsGnMaxPacketLifetime of mib
    Lifetime large_lifetime(Lifetime::Base::_100_S, 9);

    request.maximum_lifetime = large_lifetime;
    request.upper_protocol = UpperProtocol::IPv6;

    // Router handles request
    auto confirm = router.request(request, create_packet());
    EXPECT_EQ(DataConfirm::ResultCode::REJECTED_MAX_LIFETIME, confirm.result_code);
}

TEST_F(RouterRequest, modified_request_repetition)
{
    // create ShbDataRequest
    ShbDataRequest request(mib, security::Profile::CAM);

    // create durations that will fail in data_confirm
    auto rep_faulty_int = 0.0 * units::si::seconds; // this has to be lower than mib.itsGnMinPacketRepetitionInterval
    auto rep_max = 99.0 * units::si::seconds;

    // create Repetition with faulty interval
    DataRequest::Repetition rep;
    rep.interval = rep_faulty_int;
    rep.maximum = rep_max;

    request.repetition = rep;
    request.upper_protocol = UpperProtocol::IPv6;

    // Router handles request
    auto confirm = router.request(request, create_packet());
    EXPECT_EQ(DataConfirm::ResultCode::REJECTED_MIN_REPETITION_INTERVAL, confirm.result_code);
}

TEST_F(RouterRequest, modified_request_payload_null)
{
    // create ShbDataRequest
    ShbDataRequest request(mib, security::Profile::CAM);
    request.upper_protocol = UpperProtocol::IPv6;

    // Router handles request
    auto confirm = router.request(request, nullptr);
    EXPECT_EQ(DataConfirm::ResultCode::REJECTED_UNSPECIFIED, confirm.result_code);
}

TEST_F(RouterRequest, modified_request_large_payload)
{
    std::unique_ptr<geonet::DownPacket> packet { new geonet::DownPacket() };

    // create too large payload
    ByteBuffer payload_large;
    for (int i = 0; i < 1000; i++) {
        ByteBuffer tmp = {0,1,2,3,4,5,6,7,8,9};
        payload_large.insert(payload_large.end(), tmp.begin(), tmp.end());
    }

    // insert payload in packet
    packet->layer(OsiLayer::Transport) = ByteBuffer(payload_large);

    // create ShbDataRequest
    ShbDataRequest request(mib, security::Profile::CAM);
    request.upper_protocol = UpperProtocol::IPv6;

    // Router handles request
    auto confirm = router.request(request, std::move(packet));
    EXPECT_EQ(DataConfirm::ResultCode::REJECTED_MAX_SDU_SIZE, confirm.result_code);
}
