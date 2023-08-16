#include <gtest/gtest.h>
#include <vanetza/btp/header.hpp>
#include <vanetza/common/its_aid.hpp>
#include <vanetza/common/manual_runtime.hpp>
#include <vanetza/geonet/router.hpp>
#include <vanetza/geonet/tests/fake_interfaces.hpp>
#include <vanetza/geonet/tests/security_context.hpp>

using namespace vanetza;

class RouterIndicate : public ::testing::Test
{
public:
    RouterIndicate() :
        runtime(Clock::at("2010-12-23 18:29")), security(runtime), router(runtime, mib), packet_drop_occurred(false) {}

protected:
    virtual void SetUp() override
    {
        runtime.trigger(Clock::at("2010-12-23 18:30"));
        geonet::Address gn_addr;
        gn_addr.mid(MacAddress { 0, 0, 0, 0, 0, 1});
        router.set_address(gn_addr);
        router.set_access_interface(&req_ifc);
        router.set_transport_handler(geonet::UpperProtocol::IPv6, &ind_ifc);
        router.set_security_entity(&security.entity());
        packet_drop_occurred = false;
        router.packet_dropped = [this](geonet::Router::PacketDropReason r) {
            drop_reason = r;
            packet_drop_occurred = true;
        };
        test_payload_trans = {47, 11, 1, 4, 42, 85};
        test_payload_sess = {55, 1, 16, 45, 2, 65};
        test_payload_pres = {33, 2, 6, 27, 75, 1};
        send_payload.insert(send_payload.end(), test_payload_trans.begin(), test_payload_trans.end());
        send_payload.insert(send_payload.end(), test_payload_sess.begin(), test_payload_sess.end());
        send_payload.insert(send_payload.end(), test_payload_pres.begin(), test_payload_pres.end());
    }

    std::unique_ptr<geonet::DownPacket> create_packet()
    {
        std::unique_ptr<geonet::DownPacket> packet { new geonet::DownPacket() };
        packet->layer(OsiLayer::Transport) = ByteBuffer(test_payload_trans);
        packet->layer(OsiLayer::Session) = ByteBuffer(test_payload_sess);
        packet->layer(OsiLayer::Presentation) = ByteBuffer(test_payload_pres);
        return packet;
    }

    std::unique_ptr<geonet::UpPacket> get_up_packet(const ByteBuffer& sec_packet_buffer)
    {
        // parse the data into UpPacket
        std::unique_ptr<geonet::UpPacket> up_packet(new geonet::UpPacket(CohesivePacket(sec_packet_buffer, OsiLayer::Network)));
        return up_packet;
    }

    ByteBuffer create_secured_packet()
    {
        // enable security
        mib.itsGnSecurity = true;

        // create ShbDataRequest
        geonet::ShbDataRequest request(mib, aid::CA);
        request.upper_protocol = geonet::UpperProtocol::IPv6;

        // Router handles request
        auto confirm = router.request(request, create_packet());
        assert(confirm.accepted());

        // secured packet on network layer
        ByteBuffer sec_packet_buffer;
        req_ifc.m_last_packet->layer(OsiLayer::Network).convert(sec_packet_buffer);
        assert(req_ifc.m_last_packet->size(OsiLayer::Transport, max_osi_layer()) == 0);

        assert(!sec_packet_buffer.empty());
        return sec_packet_buffer;
    }

    ByteBuffer create_plain_packet()
    {
        // disable security
        mib.itsGnSecurity = false;

        // create ShbDataRequest
        geonet::ShbDataRequest request(mib, aid::CA);
        request.upper_protocol = geonet::UpperProtocol::IPv6;

        // Router handles request
        auto confirm = router.request(request, create_packet());
        assert(confirm.accepted());

        // secured packet on network layer
        ByteBuffer plain_packet_buffer;
        for (auto layer : osi_layer_range<OsiLayer::Network, max_osi_layer()>()) {
            ByteBuffer layer_buffer;
            req_ifc.m_last_packet->layer(layer).convert(layer_buffer);
            plain_packet_buffer.insert(plain_packet_buffer.end(), layer_buffer.begin(), layer_buffer.end());
        }

        assert(!plain_packet_buffer.empty());
        return plain_packet_buffer;
    }

    bool test_and_reset_packet_drop()
    {
        bool result = packet_drop_occurred;
        packet_drop_occurred = false;
        return result;
    }

    MacAddress mac_address_sender = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06};
    MacAddress mac_address_destination =  {0x07, 0x08, 0x09, 0x00, 0x01, 0x02};
    geonet::ManagementInformationBase mib;
    ManualRuntime runtime;
    SecurityContext security;
    geonet::Router router;
    geonet::Router::PacketDropReason drop_reason;
    FakeRequestInterface req_ifc;
    FakeTransportInterface ind_ifc;
    ByteBuffer test_payload_trans;
    ByteBuffer test_payload_sess;
    ByteBuffer test_payload_pres;
    ByteBuffer send_payload;

private:
    bool packet_drop_occurred;
};

TEST_F(RouterIndicate, shb_unsecured_equal_payload)
{
    // create shb-up-packet by calling request
    ByteBuffer sec_packet_buffer = create_plain_packet();
    std::unique_ptr<geonet::UpPacket> packet_up = get_up_packet(sec_packet_buffer);

    // call indicate
    router.indicate(std::move(packet_up), mac_address_sender, mac_address_destination);

    // check hook, it shouldn't have been called
    EXPECT_FALSE(test_and_reset_packet_drop());

    // check if packet was not discarded
    ASSERT_NE(nullptr, ind_ifc.m_last_packet.get());
    // prepare a packet to check it's payload
    CohesivePacket* received_payload_ptr = boost::get<CohesivePacket>(ind_ifc.m_last_packet.get());
    ASSERT_NE(nullptr, received_payload_ptr);
    // extract received payload
    auto received_payload_range = (*received_payload_ptr)[OsiLayer::Transport];
    const ByteBuffer received_payload = ByteBuffer(received_payload_range.begin(), received_payload_range.end());
    // check payload
    EXPECT_EQ(send_payload, received_payload);
}

TEST_F(RouterIndicate, shb_secured_equal_payload)
{
    // create shb-up-packet by calling request
    ByteBuffer sec_packet_buffer = create_secured_packet();
    std::unique_ptr<geonet::UpPacket> packet_up = get_up_packet(sec_packet_buffer);

    // call indicate
    router.indicate(std::move(packet_up), mac_address_sender, mac_address_destination);

    // check hook, it shouldn't have been called
    EXPECT_FALSE(test_and_reset_packet_drop()) << "Packet drop reason: " << static_cast<int>(drop_reason);

    // check if packet was not discarded
    ASSERT_NE(nullptr, ind_ifc.m_last_packet.get());
    ASSERT_TRUE(ind_ifc.m_last_indication);
    // prepare a packet to check it's payload
    CohesivePacket* received_payload_ptr = boost::get<CohesivePacket>(ind_ifc.m_last_packet.get());
    ASSERT_NE(nullptr, received_payload_ptr);
    // extract received payload
    auto received_payload_range = (*received_payload_ptr)[OsiLayer::Transport];
    const ByteBuffer received_payload = ByteBuffer(received_payload_range.begin(), received_payload_range.end());
    // check payload
    EXPECT_EQ(send_payload, received_payload);
    // check permissions are exposed correctly, these are set by NaiveCertificateProvider for the aid::CA
    ASSERT_TRUE(ind_ifc.m_last_indication.get().its_aid);
    ASSERT_TRUE(ind_ifc.m_last_indication.get().permissions);
    EXPECT_EQ(ind_ifc.m_last_indication.get().its_aid.get(), aid::CA);
    EXPECT_EQ(ind_ifc.m_last_indication.get().permissions.get(), ByteBuffer({ 1, 0, 0 }));
}

TEST_F(RouterIndicate, shb_secured_hook_its_protocol_version)
{
    // modify up_packet for negative test
    ByteBuffer broken_packet_buffer = create_secured_packet();
    broken_packet_buffer[0] ^= 0xff;

    std::unique_ptr<geonet::UpPacket> broken_packet_up = get_up_packet(broken_packet_buffer);
    router.indicate(std::move(broken_packet_up), mac_address_sender, mac_address_destination);

    // check hook
    EXPECT_TRUE(test_and_reset_packet_drop());
    EXPECT_EQ(geonet::Router::PacketDropReason::ITS_Protocol_Version, drop_reason);

    // check if packet was dropped
    EXPECT_EQ(nullptr, ind_ifc.m_last_packet.get());
}

TEST_F(RouterIndicate, shb_secured_hook_parse_basic_header)
{
    // modify up_packet for negative test
    ByteBuffer broken_packet_buffer = create_secured_packet();
    broken_packet_buffer.erase(broken_packet_buffer.begin() + 3, broken_packet_buffer.end());

    std::unique_ptr<geonet::UpPacket> broken_packet_up = get_up_packet(broken_packet_buffer);
    router.indicate(std::move(broken_packet_up), mac_address_sender, mac_address_destination);

    // check hook
    EXPECT_TRUE(test_and_reset_packet_drop());
    EXPECT_EQ(geonet::Router::PacketDropReason::Parse_Basic_Header, drop_reason);

    // check if packet was dropped
    EXPECT_EQ(nullptr, ind_ifc.m_last_packet.get());
}

TEST_F(RouterIndicate, shb_secured_hook_parse_secured_header)
{
    // modify up_packet for negative test
    ByteBuffer broken_packet_buffer = create_secured_packet();
    broken_packet_buffer[geonet::BasicHeader::length_bytes] = 0x01;

    std::unique_ptr<geonet::UpPacket> broken_packet_up = get_up_packet(broken_packet_buffer);
    router.indicate(std::move(broken_packet_up), mac_address_sender, mac_address_destination);

    // check hook
    EXPECT_TRUE(test_and_reset_packet_drop());
    EXPECT_EQ(geonet::Router::PacketDropReason::Parse_Secured_Header, drop_reason);

    // check if packet was dropped
    EXPECT_EQ(nullptr, ind_ifc.m_last_packet.get());
}

TEST_F(RouterIndicate, shb_secured_hook_decap_unsuccessful_non_strict)
{
    mib.itsGnSnDecapResultHandling = geonet::SecurityDecapHandling::Non_Strict;

    // modify up_packet for positive test
    ByteBuffer broken_packet_buffer = create_secured_packet();
    broken_packet_buffer[broken_packet_buffer.size() - 1] ^= 0xff;

    std::unique_ptr<geonet::UpPacket> broken_packet_up = get_up_packet(broken_packet_buffer);
    router.indicate(std::move(broken_packet_up), mac_address_sender, mac_address_destination);

    // check hook
    EXPECT_FALSE(test_and_reset_packet_drop());

    // check if packet arrived at transport layer
    EXPECT_EQ(1, ind_ifc.m_indications);
    EXPECT_NE(nullptr, ind_ifc.m_last_packet.get());
}

TEST_F(RouterIndicate, shb_secured_hook_decap_unsuccessful_strict)
{
    mib.itsGnSnDecapResultHandling = geonet::SecurityDecapHandling::Strict;

    // modify up_packet for negative test
    ByteBuffer broken_packet_buffer = create_secured_packet();
    broken_packet_buffer[broken_packet_buffer.size() - 1] ^= 0xff;

    std::unique_ptr<geonet::UpPacket> broken_packet_up = get_up_packet(broken_packet_buffer);
    router.indicate(std::move(broken_packet_up), mac_address_sender, mac_address_destination);

    // check hook
    EXPECT_TRUE(test_and_reset_packet_drop());
    EXPECT_EQ(geonet::Router::PacketDropReason::Decap_Unsuccessful_Strict, drop_reason);

    // check if packet was dropped
    EXPECT_EQ(nullptr, ind_ifc.m_last_packet.get());
}

TEST_F(RouterIndicate, shb_secured_hook_parse_extended_header)
{
    // modify up_packet for negative test
    ByteBuffer broken_packet_buffer = create_plain_packet();
    // cut extended header partly off (18 bytes payload)
    ASSERT_LT(32, broken_packet_buffer.size());
    broken_packet_buffer.erase(broken_packet_buffer.end() - 32, broken_packet_buffer.end());

    std::unique_ptr<geonet::UpPacket> broken_packet_up = get_up_packet(broken_packet_buffer);
    router.indicate(std::move(broken_packet_up), mac_address_sender, mac_address_destination);

    // check hook
    EXPECT_TRUE(test_and_reset_packet_drop());
    EXPECT_EQ(geonet::Router::PacketDropReason::Parse_Extended_Header, drop_reason);

    // check if packet was dropped
    EXPECT_EQ(nullptr, ind_ifc.m_last_packet.get());
}

TEST_F(RouterIndicate, shb_secured_hook_payload_size)
{
    // modify up_packet for negative test
    ByteBuffer broken_packet_buffer = create_plain_packet();
    // cut payload partly off (18 bytes payload)
    ASSERT_LT(7, broken_packet_buffer.size());
    broken_packet_buffer.erase(broken_packet_buffer.end() - 7, broken_packet_buffer.end());

    std::unique_ptr<geonet::UpPacket> broken_packet_up = get_up_packet(broken_packet_buffer);
    router.indicate(std::move(broken_packet_up), mac_address_sender, mac_address_destination);

    // check hook
    EXPECT_TRUE(test_and_reset_packet_drop());
    EXPECT_EQ(geonet::Router::PacketDropReason::Payload_Size, drop_reason);

    // check if packet was dropped
    EXPECT_EQ(nullptr, ind_ifc.m_last_packet.get());
}

TEST_F(RouterIndicate, shb_secured_hook_hop_limit)
{
    // modify up_packet for negative test
    ByteBuffer broken_packet_buffer = create_secured_packet();
    // resest hop limit in basic header
    broken_packet_buffer[geonet::BasicHeader::length_bytes - 1] = mib.itsGnDefaultHopLimit + 1;

    std::unique_ptr<geonet::UpPacket> broken_packet_up = get_up_packet(broken_packet_buffer);
    router.indicate(std::move(broken_packet_up), mac_address_sender, mac_address_destination);

    // check hook
    EXPECT_TRUE(test_and_reset_packet_drop());
    EXPECT_EQ(geonet::Router::PacketDropReason::Hop_Limit, drop_reason);

    // check if packet was dropped
    EXPECT_EQ(nullptr, ind_ifc.m_last_packet.get());
}

TEST_F(RouterIndicate, shb_secured_hook_unsecured_packet)
{
    // modify up_packet for negative test
    ByteBuffer packet_buffer = create_plain_packet();

    // enable security after create_plain_packet() disabled it
    mib.itsGnSecurity = true;

    std::unique_ptr<geonet::UpPacket> packet_up = get_up_packet(packet_buffer);
    router.indicate(std::move(packet_up), mac_address_sender, mac_address_destination);

    // check hook
    EXPECT_TRUE(test_and_reset_packet_drop());
    EXPECT_EQ(geonet::Router::PacketDropReason::Decap_Unsuccessful_Strict, drop_reason);

    // check if packet was dropped
    EXPECT_EQ(nullptr, ind_ifc.m_last_packet.get());
}

TEST_F(RouterIndicate, shb_secured_hook_unsecured_packet_nonstrict)
{
    // modify up_packet for negative test
    ByteBuffer packet_buffer = create_plain_packet();

    // enable security after create_plain_packet() disabled it
    mib.itsGnSecurity = true;
    mib.itsGnSnDecapResultHandling = geonet::SecurityDecapHandling::Non_Strict;

    std::unique_ptr<geonet::UpPacket> packet_up = get_up_packet(packet_buffer);
    router.indicate(std::move(packet_up), mac_address_sender, mac_address_destination);

    // check hook
    EXPECT_FALSE(test_and_reset_packet_drop());
    // check if packet was not discarded
    ASSERT_NE(nullptr, ind_ifc.m_last_packet.get());
    ASSERT_TRUE(ind_ifc.m_last_indication);
    // prepare a packet to check it's payload
    CohesivePacket* received_payload_ptr = boost::get<CohesivePacket>(ind_ifc.m_last_packet.get());
    ASSERT_NE(nullptr, received_payload_ptr);
    // extract received payload
    auto received_payload_range = (*received_payload_ptr)[OsiLayer::Transport];
    const ByteBuffer received_payload = ByteBuffer(received_payload_range.begin(), received_payload_range.end());
    // check payload
    EXPECT_EQ(send_payload, received_payload);
}

TEST_F(RouterIndicate, shb_secured_v3_message_digest)
{
    mac_address_sender = MacAddress { 0xfe, 0x38, 0x4c, 0xe0, 0xb8, 0x90 };
    mac_address_destination = MacAddress { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    const ByteBuffer gn_buffer = {
        0x12, 0x00, 0x05, 0x01, 0x03, 0x81, 0x00, 0x40,
        0x03, 0x80, 0x56, 0x20, 0x50, 0x02, 0x80, 0x00,
        0x32, 0x01, 0x00, 0x14, 0x00, 0xfe, 0x38, 0x4c,
        0xe0, 0xb8, 0x90, 0xbf, 0x6b, 0x2b, 0x74, 0x1f,
        0x45, 0x28, 0x68, 0x06, 0x64, 0x09, 0x65, 0x80,
        0x42, 0x03, 0xbf, 0x00, 0x00, 0xa0, 0x00, 0x07,
        0xd1, 0x00, 0x00, 0x02, 0x02, 0x4c, 0xe0, 0xb8,
        0x90, 0x2e, 0x6b, 0x00, 0x5a, 0x9d, 0x42, 0x2b,
        0xce, 0x35, 0xbb, 0x82, 0x02, 0x3c, 0x23, 0x06,
        0xda, 0x35, 0x96, 0xd4, 0x58, 0x3b, 0xe1, 0x20,
        0x6d, 0x03, 0x02, 0x96, 0x8a, 0xcb, 0x33, 0xe6,
        0x61, 0xff, 0xaa, 0x10, 0x3f, 0xe0, 0x14, 0x19,
        0x80, 0x40, 0x01, 0x24, 0x00, 0x01, 0xc8, 0x0b,
        0xba, 0xad, 0xa0, 0x64, 0x80, 0x12, 0x7c, 0xff,
        0x38, 0x4c, 0xe0, 0xb8, 0x90, 0x80, 0x82, 0x9d,
        0xee, 0xde, 0x15, 0x9a, 0x66, 0x08, 0x1d, 0x03,
        0x6f, 0x7b, 0x28, 0x2d, 0x8f, 0xf0, 0x43, 0xc6,
        0x35, 0x5f, 0x51, 0x07, 0x65, 0xb1, 0x42, 0x77,
        0xb7, 0x72, 0x27, 0x15, 0x59, 0x0c, 0x9e, 0x47,
        0x82, 0xfc, 0xbe, 0xe3, 0x3a, 0xbc, 0x51, 0x93,
        0xfb, 0xbd, 0xa7, 0xf0, 0x4f, 0xde, 0xb2, 0xfe,
        0x88, 0xa5, 0x19, 0x5e, 0xa7, 0x03, 0xca, 0xf4,
        0x12, 0x21, 0x32, 0x37, 0xe8, 0x5d, 0xda
    };

    // gn_buffer contains a CAM using BTP-B transport
    router.set_transport_handler(geonet::UpperProtocol::BTP_B, &ind_ifc);
    router.set_transport_handler(geonet::UpperProtocol::IPv6, nullptr);

    // message with digest will not be accepted because its certificate is unknown
    EXPECT_EQ(security.certificate_cache_v3().size(), 0);
    router.indicate(get_up_packet(gn_buffer), mac_address_sender, mac_address_destination);
    EXPECT_TRUE(test_and_reset_packet_drop());

    // add certificate manually to certificate cache
    const ByteBuffer certificate_buffer = {
        0x80, 0x03, 0x00, 0x80, 0x56, 0xdf, 0xd6, 0xd6,
        0x27, 0xa3, 0x62, 0xdc, 0x10, 0x83, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x1d, 0xdf, 0xf7, 0xb5, 0x84,
        0x00, 0xa8, 0x01, 0x02, 0x80, 0x01, 0x24, 0x81,
        0x04, 0x03, 0x01, 0x00, 0x00, 0x80, 0x01, 0x25,
        0x81, 0x05, 0x04, 0x01, 0x90, 0x1a, 0x25, 0x80,
        0x80, 0x82, 0x04, 0x27, 0xbb, 0x27, 0xc9, 0x98,
        0xc1, 0xec, 0xa2, 0xb1, 0x0e, 0x71, 0x07, 0x98,
        0x02, 0x44, 0x51, 0x8b, 0x3c, 0x50, 0xa3, 0xa3,
        0x27, 0xb5, 0xb1, 0x90, 0xd0, 0x90, 0xf1, 0x45,
        0x1f, 0x3d, 0x80, 0x80, 0x83, 0xc2, 0xf3, 0xca,
        0xeb, 0xc7, 0xfa, 0x35, 0x94, 0x5c, 0x03, 0x0a,
        0x5a, 0xe0, 0x1a, 0x41, 0x7a, 0xdf, 0x6d, 0xff,
        0xd5, 0x41, 0xcc, 0xd2, 0xd9, 0x2b, 0xfe, 0xb6,
        0x3d, 0xc1, 0x56, 0x89, 0xcb, 0xd6, 0xb8, 0xe3,
        0x2b, 0xd5, 0xe8, 0x66, 0xd9, 0xfa, 0xa2, 0xfe,
        0x55, 0x95, 0xe2, 0xdb, 0xb9, 0xbe, 0x3e, 0x96,
        0x5a, 0x70, 0x94, 0x25, 0x8b, 0x4a, 0x24, 0x9d,
        0xfb, 0x75, 0x8a, 0x07
    };
    security::v3::Certificate certificate;
    EXPECT_TRUE(certificate.decode(certificate_buffer));
    security.certificate_cache_v3().store(certificate);
    EXPECT_EQ(security.certificate_cache_v3().size(), 1);

    // expect that same message is now accepted
    router.indicate(get_up_packet(gn_buffer), mac_address_sender, mac_address_destination);
    EXPECT_FALSE(test_and_reset_packet_drop()) << "Packet drop reason: " << static_cast<int>(drop_reason);

    // assure that packet has been passed to transport layer
    ASSERT_TRUE(ind_ifc.m_last_indication);
    EXPECT_EQ(ind_ifc.m_last_indication->upper_protocol, geonet::UpperProtocol::BTP_B);
    EXPECT_EQ(ind_ifc.m_last_indication->security_report, security::DecapReport::Success);
    EXPECT_EQ(ind_ifc.m_last_indication->its_aid, aid::CA);

    ASSERT_TRUE(ind_ifc.m_last_packet);
}

TEST_F(RouterIndicate, shb_secured_v3_message_certificate)
{
    mac_address_sender = MacAddress { 0xfe, 0x38, 0x4c, 0xe0, 0xb8, 0x90 };
    mac_address_destination = MacAddress { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    const ByteBuffer gn_buffer = {
        0x12, 0x00, 0x05, 0x01, 0x03, 0x81, 0x00, 0x40,
        0x03, 0x80, 0x56, 0x20, 0x50, 0x02, 0x80, 0x00,
        0x32, 0x01, 0x00, 0x14, 0x00, 0xfe, 0x38, 0x4c,
        0xe0, 0xb8, 0x90, 0xbf, 0x6b, 0x33, 0x44, 0x1f,
        0x45, 0x28, 0x40, 0x06, 0x64, 0x0c, 0x70, 0x81,
        0xae, 0x03, 0xbd, 0x00, 0x00, 0xa0, 0x00, 0x07,
        0xd1, 0x00, 0x00, 0x02, 0x02, 0x4c, 0xe0, 0xb8,
        0x90, 0x35, 0x71, 0x00, 0x5a, 0x9d, 0x42, 0x25,
        0xee, 0x35, 0xbb, 0xfc, 0x82, 0x4a, 0x24, 0x46,
        0xd8, 0x35, 0xa3, 0x54, 0x58, 0x3b, 0xe1, 0x21,
        0x00, 0x83, 0x02, 0x96, 0x8a, 0xaf, 0x33, 0xf0,
        0x81, 0xfe, 0x9a, 0x10, 0x3f, 0xa0, 0x14, 0x19,
        0x80, 0x40, 0x01, 0x24, 0x00, 0x01, 0xc8, 0x0b,
        0xba, 0xc9, 0x16, 0xae, 0x81, 0x01, 0x01, 0x80,
        0x03, 0x00, 0x80, 0x56, 0xdf, 0xd6, 0xd6, 0x27,
        0xa3, 0x62, 0xdc, 0x10, 0x83, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x1d, 0xdf, 0xf7, 0xb5, 0x84, 0x00,
        0xa8, 0x01, 0x02, 0x80, 0x01, 0x24, 0x81, 0x04,
        0x03, 0x01, 0x00, 0x00, 0x80, 0x01, 0x25, 0x81,
        0x05, 0x04, 0x01, 0x90, 0x1a, 0x25, 0x80, 0x80,
        0x82, 0x04, 0x27, 0xbb, 0x27, 0xc9, 0x98, 0xc1,
        0xec, 0xa2, 0xb1, 0x0e, 0x71, 0x07, 0x98, 0x02,
        0x44, 0x51, 0x8b, 0x3c, 0x50, 0xa3, 0xa3, 0x27,
        0xb5, 0xb1, 0x90, 0xd0, 0x90, 0xf1, 0x45, 0x1f,
        0x3d, 0x80, 0x80, 0x83, 0xc2, 0xf3, 0xca, 0xeb,
        0xc7, 0xfa, 0x35, 0x94, 0x5c, 0x03, 0x0a, 0x5a,
        0xe0, 0x1a, 0x41, 0x7a, 0xdf, 0x6d, 0xff, 0xd5,
        0x41, 0xcc, 0xd2, 0xd9, 0x2b, 0xfe, 0xb6, 0x3d,
        0xc1, 0x56, 0x89, 0xcb, 0xd6, 0xb8, 0xe3, 0x2b,
        0xd5, 0xe8, 0x66, 0xd9, 0xfa, 0xa2, 0xfe, 0x55,
        0x95, 0xe2, 0xdb, 0xb9, 0xbe, 0x3e, 0x96, 0x5a,
        0x70, 0x94, 0x25, 0x8b, 0x4a, 0x24, 0x9d, 0xfb,
        0x75, 0x8a, 0x07, 0x80, 0x82, 0xf4, 0x4c, 0xc3,
        0xc3, 0xb1, 0x0c, 0xf7, 0x7c, 0xd9, 0x0c, 0x40,
        0xfe, 0xe7, 0x30, 0x40, 0xad, 0x0b, 0xb4, 0xf8,
        0x34, 0x55, 0x81, 0x37, 0xa6, 0x96, 0x81, 0x78,
        0xe0, 0x53, 0x09, 0x06, 0xf7, 0x4f, 0x14, 0x43,
        0x46, 0x88, 0x29, 0x6e, 0x22, 0xfe, 0xbb, 0x6f,
        0x8e, 0x21, 0xad, 0x51, 0x7e, 0xb0, 0x81, 0x9a,
        0x39, 0xf2, 0xaa, 0xd3, 0x37, 0x51, 0xf3, 0xab,
        0xde, 0xdd, 0x69, 0xfe, 0xaf
    };
    // gn_buffer contains a CAM using BTP-B transport
    router.set_transport_handler(geonet::UpperProtocol::BTP_B, &ind_ifc);
    router.set_transport_handler(geonet::UpperProtocol::IPv6, nullptr);

    router.indicate(get_up_packet(gn_buffer), mac_address_sender, mac_address_destination);

    // assure that packet has not been dropped
    EXPECT_FALSE(test_and_reset_packet_drop()) << "Packet drop reason: " << static_cast<int>(drop_reason);

    // assure that packet has been passed to transport layer
    ASSERT_TRUE(ind_ifc.m_last_indication);
    EXPECT_EQ(ind_ifc.m_last_indication->upper_protocol, geonet::UpperProtocol::BTP_B);
    EXPECT_EQ(ind_ifc.m_last_indication->security_report, security::DecapReport::Success);
    EXPECT_EQ(ind_ifc.m_last_indication->its_aid, aid::CA);

    ASSERT_TRUE(ind_ifc.m_last_packet);
}
