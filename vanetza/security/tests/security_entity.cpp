#include <gtest/gtest.h>
#include <vanetza/common/clock.hpp>
#include <vanetza/geonet/mib.hpp>
#include <vanetza/security/security_entity.hpp>
#include <vanetza/security/tests/check_payload.hpp>

using namespace vanetza;
using namespace vanetza::security;

class SecurityEntityTest : public ::testing::Test
{
protected:
    SecurityEntityTest() : sec_ent(time_now)
    {
    }

    void SetUp() override
    {
        expected_payload[OsiLayer::Transport] = ByteBuffer {89, 27, 1, 4, 18, 85};
    }

    EncapRequest create_encap_request()
    {
        EncapRequest encap_request;
        encap_request.plaintext_payload = expected_payload;
        encap_request.security_profile = Profile::CAM;
        return encap_request;
    }

    Clock::time_point time_now;
    SecurityEntity sec_ent;
    ChunkPacket expected_payload;
};

TEST_F(SecurityEntityTest, mutual_acceptance)
{
    SecurityEntity other_sec_ent(time_now);
    EncapConfirm encap_confirm = other_sec_ent.encapsulate_packet(create_encap_request());
    DecapConfirm decap_confirm = sec_ent.decapsulate_packet(DecapRequest { encap_confirm.sec_packet });
    EXPECT_EQ(ReportType::Success, decap_confirm.report);
}

TEST_F(SecurityEntityTest, signed_payload_equals_plaintext_payload)
{
    EncapConfirm confirm = sec_ent.encapsulate_packet(create_encap_request());

    // check if sec_payload equals plaintext_payload
    check(expected_payload, confirm.sec_packet.payload.data);
}

TEST_F(SecurityEntityTest, signature_is_ecdsa)
{
    EncapConfirm confirm = sec_ent.encapsulate_packet(create_encap_request());

    // check if trailer_fields contain signature
    ASSERT_EQ(1, confirm.sec_packet.trailer_fields.size());
    // check trailer field type
    ASSERT_EQ(TrailerFieldType::Signature, get_type(confirm.sec_packet.trailer_fields.front()));
    // check signature type
    Signature signature = boost::get<Signature>(confirm.sec_packet.trailer_fields.front());
    EXPECT_EQ(PublicKeyAlgorithm::Ecdsa_Nistp256_With_Sha256, get_type(signature));
}

TEST_F(SecurityEntityTest, expected_header_field_size)
{
    EncapConfirm confirm = sec_ent.encapsulate_packet(create_encap_request());

    // check header_field size
    EXPECT_EQ(3, confirm.sec_packet.header_fields.size());
}

TEST_F(SecurityEntityTest, expected_payload)
{
    EncapConfirm confirm = sec_ent.encapsulate_packet(create_encap_request());

    // check payload
    Payload payload = confirm.sec_packet.payload;
    EXPECT_EQ(expected_payload.size(), size(payload.data, min_osi_layer(), max_osi_layer()));
    EXPECT_EQ(PayloadType::Signed, get_type(payload));
}


TEST_F(SecurityEntityTest, test_verify_method)
{
    //create signed packet
    EncapRequest encap_request = create_encap_request();
    EncapConfirm encap_confirm;
    encap_confirm = sec_ent.encapsulate_packet(encap_request);

    //create decap_request
    DecapRequest decap_request(encap_confirm.sec_packet);

    //create decap_confirm
    DecapConfirm decap_confirm;
    decap_confirm = sec_ent.decapsulate_packet(decap_request);

    //check ReportType of decap_confirm
    EXPECT_EQ(decap_confirm.report, ReportType::Success);
}

TEST_F(SecurityEntityTest, test_verify_method_fail)
{
    //create signed packet
    EncapRequest encap_request = create_encap_request();
    EncapConfirm encap_confirm;
    encap_confirm = sec_ent.encapsulate_packet(encap_request);
    SecuredMessage& secured_message = encap_confirm.sec_packet;

    //create decap_request of signed packet
    DecapRequest decap_request(secured_message);

    //create new (wrong) payload
    ByteBuffer wrong_payload { 7 };

    //replace correct payload with new payload
    secured_message.payload.data = CohesivePacket(wrong_payload, OsiLayer::Application);

    //create decap_confirm
    DecapConfirm decap_confirm;
    decap_confirm = sec_ent.decapsulate_packet(decap_request);

    //check ReportType of decap_confirm
    EXPECT_EQ(decap_confirm.report, ReportType::False_Signature);
}
