#include <gtest/gtest.h>
#include <vanetza/common/clock.hpp>
#include <vanetza/geonet/mib.hpp>
#include <vanetza/security/security_entity.hpp>
#include <vanetza/security/tests/check_payload.hpp>

using namespace vanetza;
using vanetza::security::check;

class SecurityEntity : public ::testing::Test
{
protected:
    SecurityEntity() : sec_ent(time_now)
    {
    }

    void SetUp() override
    {
        expected_payload[OsiLayer::Transport] = ByteBuffer {89, 27, 1, 4, 18, 85};
    }

    security::EncapRequest create_encap_request()
    {
        security::EncapRequest encap_request;
        encap_request.plaintext_payload = expected_payload;
        encap_request.security_profile = security::Profile::CAM;
        return encap_request;
    }

    Clock::time_point time_now;
    security::SecurityEntity sec_ent;
    ChunkPacket expected_payload;
};

TEST_F(SecurityEntity, mutual_acceptance)
{
    security::SecurityEntity other_sec_ent(time_now);
    security::EncapConfirm encap_confirm = other_sec_ent.encapsulate_packet(create_encap_request());
    security::DecapConfirm decap_confirm = sec_ent.decapsulate_packet(security::DecapRequest { encap_confirm.sec_packet });
    EXPECT_EQ(security::ReportType::Success, decap_confirm.report);
}

TEST_F(SecurityEntity, signed_payload_equals_plaintext_payload)
{
    security::EncapConfirm confirm = sec_ent.encapsulate_packet(create_encap_request());

    // check if sec_payload equals plaintext_payload
    check(expected_payload, confirm.sec_packet.payload.data);
}

TEST_F(SecurityEntity, signature_is_ecdsa)
{
    security::EncapConfirm confirm = sec_ent.encapsulate_packet(create_encap_request());

    // check if trailer_fields contain signature
    ASSERT_EQ(1, confirm.sec_packet.trailer_fields.size());
    // check trailer field type
    ASSERT_EQ(security::TrailerFieldType::Signature, get_type(confirm.sec_packet.trailer_fields.front()));
    // check signature type
    security::Signature signature = boost::get<security::Signature>(confirm.sec_packet.trailer_fields.front());
    EXPECT_EQ(security::PublicKeyAlgorithm::Ecdsa_Nistp256_With_Sha256, get_type(signature));
}

TEST_F(SecurityEntity, expected_header_field_size)
{
    security::EncapConfirm confirm = sec_ent.encapsulate_packet(create_encap_request());

    // check header_field size
    EXPECT_EQ(3, confirm.sec_packet.header_fields.size());
}

TEST_F(SecurityEntity, expected_payload)
{
    security::EncapConfirm confirm = sec_ent.encapsulate_packet(create_encap_request());

    // check payload
    security::Payload payload = confirm.sec_packet.payload;
    EXPECT_EQ(expected_payload.size(), size(payload.data, min_osi_layer(), max_osi_layer()));
    EXPECT_EQ(security::PayloadType::Signed, get_type(payload));
}


TEST_F(SecurityEntity, test_verify_method)
{
    //create signed packet
    security::EncapRequest encap_request = create_encap_request();
    security::EncapConfirm encap_confirm;
    encap_confirm = sec_ent.encapsulate_packet(encap_request);

    //create decap_request
    security::DecapRequest decap_request(encap_confirm.sec_packet);

    //create decap_confirm
    security::DecapConfirm decap_confirm;
    decap_confirm = sec_ent.decapsulate_packet(decap_request);

    //check ReportType of decap_confirm
    EXPECT_EQ(decap_confirm.report, security::ReportType::Success);
}

TEST_F(SecurityEntity, test_verify_method_fail)
{
    //create signed packet
    security::EncapRequest encap_request = create_encap_request();
    security::EncapConfirm encap_confirm;
    encap_confirm = sec_ent.encapsulate_packet(encap_request);
    security::SecuredMessage& secured_message = encap_confirm.sec_packet;

    //create decap_request of signed packet
    security::DecapRequest decap_request(secured_message);

    //create new (wrong) payload
    ByteBuffer wrong_payload { 7 };

    //replace correct payload with new payload
    secured_message.payload.data = CohesivePacket(wrong_payload, OsiLayer::Application);

    //create decap_confirm
    security::DecapConfirm decap_confirm;
    decap_confirm = sec_ent.decapsulate_packet(decap_request);

    //check ReportType of decap_confirm
    EXPECT_EQ(decap_confirm.report, security::ReportType::False_Signature);
}
