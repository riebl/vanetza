#include <gtest/gtest.h>
#include <vanetza/geonet/mib.hpp>
#include <vanetza/security/security_entity.hpp>

using namespace vanetza;

class SecurityEntity : public ::testing::Test
{
protected:
    security::EncapRequest create_encap_request()
    {
        geonet::ManagementInformationBase mib;
        geonet::ExtendedPdu<geonet::ShbHeader> epdu = geonet::ExtendedPdu<geonet::ShbHeader>(mib);
        const ByteBuffer send_payload {
            89, 27, 1, 4, 18, 85
        };

        security::EncapRequest encap_request;
        encap_request.plaintext_pdu = convert_for_signing(epdu);
        encap_request.plaintext_payload = send_payload;

        return encap_request;
    }

    geonet::Timestamp time_now;
};

TEST_F(SecurityEntity, test_sign_method)
{
    //create SecurityEntity
    security::SecurityEntity sec_ent(time_now);

    //create signed packet
    security::EncapRequest encap_request = create_encap_request();
    security::EncapConfirm encap_confirm;
    encap_confirm = sec_ent.encapsulate_packet(encap_request);

    //SecuredMessage should not be empty
    EXPECT_GT(get_size(encap_confirm.sec_packet), 0);

    //check payload type
    EXPECT_EQ(encap_confirm.sec_packet.payload.type, security::PayloadType::Signed);

    //check if bytebuffers are the same
    EXPECT_EQ(encap_request.plaintext_payload, encap_confirm.sec_packet.payload.buffer);
}

TEST_F(SecurityEntity, test_verify_method)
{
    //create SecurityEntity
    security::SecurityEntity sec_ent(time_now);

    //create signed packet
    security::EncapRequest encap_request = create_encap_request();
    security::EncapConfirm encap_confirm;
    encap_confirm = sec_ent.encapsulate_packet(encap_request);

    //create decap_request
    security::DecapRequest decap_request;
    decap_request.sec_pdu = encap_request.plaintext_pdu;
    decap_request.sec_packet = encap_confirm.sec_packet;

    //create decap_confirm
    security::DecapConfirm decap_confirm;
    decap_confirm = sec_ent.decapsulate_packet(decap_request);

    //check ReportType of decap_confirm
    EXPECT_EQ(decap_confirm.report, security::ReportType::Success);
}

TEST_F(SecurityEntity, test_verify_method_fail)
{
    //create SecurityEntity
    security::SecurityEntity sec_ent(time_now);

    //create signed packet
    security::EncapRequest encap_request = create_encap_request();
    security::EncapConfirm encap_confirm;
    encap_confirm = sec_ent.encapsulate_packet(encap_request);

    //create decap_request
    security::DecapRequest decap_request;
    decap_request.sec_pdu = encap_request.plaintext_pdu;

    //create new (wrong) payload
    ByteBuffer wrong_payload { 7 };

    //get signed packet in the decap_request
    decap_request.sec_packet = encap_confirm.sec_packet;

    //replace correct payload with new payload
    decap_request.sec_packet.payload.buffer = wrong_payload;

    //create decap_confirm
    security::DecapConfirm decap_confirm;
    decap_confirm = sec_ent.decapsulate_packet(decap_request);

    //check ReportType of decap_confirm
    EXPECT_EQ(decap_confirm.report, security::ReportType::False_Signature);
}
