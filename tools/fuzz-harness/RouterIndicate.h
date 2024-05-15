#include <vanetza/btp/header.hpp>
#include <vanetza/common/its_aid.hpp>
#include <vanetza/common/manual_runtime.hpp>
#include <vanetza/geonet/router.hpp>
#include <vanetza/geonet/tests/fake_interfaces.hpp>
#include <vanetza/geonet/tests/security_context.hpp>

#ifndef VANETZA_ROUTERINDICATE_H
#define VANETZA_ROUTERINDICATE_H


class RouterIndicate {
public:
    RouterIndicate() : runtime(Clock::at("2010-12-23 18:29")), security(runtime), router(runtime, mib),
                       packet_drop_occurred(false) {
    }

    void SetUp() {
        runtime.trigger(Clock::at("2010-12-23 18:30"));
        geonet::Address gn_addr;
        gn_addr.mid(MacAddress{0, 0, 0, 0, 0, 1});
        router.set_address(gn_addr);
        router.set_access_interface(&req_ifc);
        router.set_transport_handler(geonet::UpperProtocol::BTP_B, &ind_ifc);
        router.set_transport_handler(geonet::UpperProtocol::IPv6, nullptr);
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

    std::unique_ptr<geonet::UpPacket> get_up_packet(const ByteBuffer &sec_packet_buffer) {
        // parse the data into UpPacket
        std::unique_ptr<geonet::UpPacket> up_packet(
            new geonet::UpPacket(CohesivePacket(sec_packet_buffer, OsiLayer::Network)));
        return up_packet;
    }

    MacAddress mac_address_sender = MacAddress{0xfe, 0x38, 0x4c, 0xe0, 0xb8, 0x90};
    MacAddress mac_address_destination = MacAddress{0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
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


#endif //VANETZA_ROUTERINDICATE_H
