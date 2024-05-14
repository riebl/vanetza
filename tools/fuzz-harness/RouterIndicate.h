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

    std::unique_ptr<geonet::DownPacket> create_packet() {
        std::unique_ptr<geonet::DownPacket> packet{new geonet::DownPacket()};
        packet->layer(OsiLayer::Transport) = ByteBuffer(test_payload_trans);
        packet->layer(OsiLayer::Session) = ByteBuffer(test_payload_sess);
        packet->layer(OsiLayer::Presentation) = ByteBuffer(test_payload_pres);
        return packet;
    }

    std::unique_ptr<geonet::UpPacket> get_up_packet(const ByteBuffer &sec_packet_buffer) {
        // parse the data into UpPacket
        std::unique_ptr<geonet::UpPacket> up_packet(
            new geonet::UpPacket(CohesivePacket(sec_packet_buffer, OsiLayer::Network)));
        return up_packet;
    }

    ByteBuffer create_secured_packet() {
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

    ByteBuffer create_plain_packet() {
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
        for (auto layer: osi_layer_range<OsiLayer::Network, max_osi_layer()>()) {
            ByteBuffer layer_buffer;
            req_ifc.m_last_packet->layer(layer).convert(layer_buffer);
            plain_packet_buffer.insert(plain_packet_buffer.end(), layer_buffer.begin(), layer_buffer.end());
        }

        assert(!plain_packet_buffer.empty());
        return plain_packet_buffer;
    }

    bool test_and_reset_packet_drop() {
        bool result = packet_drop_occurred;
        packet_drop_occurred = false;
        return result;
    }

    MacAddress mac_address_sender = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06};
    MacAddress mac_address_destination = {0x07, 0x08, 0x09, 0x00, 0x01, 0x02};
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
