#include <vanetza/common/byte_buffer.hpp>
#include <vanetza/common/byte_sequence.hpp>
#include <vanetza/security/basic_elements.hpp>
#include <vanetza/security/certificate_manager.hpp>
#include <vanetza/security/encap_request.hpp>
#include <vanetza/security/encap_confirm.hpp>
#include <vanetza/security/decap_request.hpp>
#include <vanetza/security/decap_confirm.hpp>
#include <vanetza/security/public_key.hpp>
#include <vanetza/security/ecc_point.hpp>
#include <vanetza/security/payload.hpp>
#include <vanetza/security/profile.hpp>
#include <vanetza/security/trailer_field.hpp>
#include <vanetza/security/tests/check_signature.hpp>
#include <gtest/gtest.h>

using namespace vanetza;

class CertificateManager : public ::testing::Test
{
public:
    CertificateManager() : time_now(0), cert_manager(time_now)
    {
    }

protected:
    virtual void SetUp() override
    {
        encap_request.plaintext_pdu = expected_pdu;
        encap_request.plaintext_payload = expected_payload;
        encap_request.security_profile = security::Profile::CAM;
    }

    security::DecapRequest getDecapRequest()
    {
        // sign message
        security::EncapConfirm encap_confirm = cert_manager.sign_message(encap_request);

        // prepare secured message
        security::SecuredMessage secured_message = encap_confirm.sec_packet;

        // prepare decap request
        security::DecapRequest decap_request;
        decap_request.sec_pdu = encap_request.plaintext_pdu;
        decap_request.sec_packet = secured_message;

        return decap_request;
    }

    ByteBuffer expected_pdu = {21, 42, 23, 15, 8};
    ByteBuffer expected_payload = {8, 25, 13, 2};
    security::EncapRequest encap_request;
    geonet::Timestamp time_now;
    security::CertificateManager cert_manager;
};

TEST_F(CertificateManager, sign_smoke_test)
{
    security::EncapConfirm confirm = cert_manager.sign_message(encap_request);
}

TEST_F(CertificateManager, sec_payload_equals_plaintext_payload)
{
    security::EncapConfirm confirm = cert_manager.sign_message(encap_request);

    // check if sec_payload equals plaintext_payload
    EXPECT_EQ(expected_payload, confirm.sec_packet.payload.buffer);
}

TEST_F(CertificateManager, signature_is_ecdsa)
{
    security::EncapConfirm confirm = cert_manager.sign_message(encap_request);

    // check if signature was set into trailer_fields
    ASSERT_EQ(1, confirm.sec_packet.trailer_fields.size());
    // check if type is correct
    ASSERT_EQ(security::TrailerFieldType::Signature, get_type(confirm.sec_packet.trailer_fields.front()));
    // check signature type
    security::Signature signature = boost::get<security::Signature>(confirm.sec_packet.trailer_fields.front());
    EXPECT_EQ(security::PublicKeyAlgorithm::Ecdsa_Nistp256_With_Sha256, get_type(signature));
}

TEST_F(CertificateManager, expected_header_field_size)
{
    security::EncapConfirm confirm = cert_manager.sign_message(encap_request);

    // check header_field size
    EXPECT_EQ(3, confirm.sec_packet.header_fields.size());
}

TEST_F(CertificateManager, expected_payload)
{
    security::EncapConfirm confirm = cert_manager.sign_message(encap_request);

    // check payload
    security::Payload payload = confirm.sec_packet.payload;
    // TODO (simon, markus): check ETSI standard whether entire payload is in secured message when security is enabled
    EXPECT_EQ(expected_payload.size(), payload.buffer.size());
    EXPECT_EQ(security::PayloadType::Signed, get_type(payload));
}

TEST_F(CertificateManager, verify_message)
{
    // prepare decap request
    security::DecapRequest decap_request = getDecapRequest();

    // verify message
    security::DecapConfirm decap_confirm = cert_manager.verify_message(decap_request);

    // check if verify was successful
    EXPECT_EQ(security::ReportType::Success, decap_confirm.report);
    // check if payload was not changed
    EXPECT_EQ(expected_payload, decap_confirm.plaintext_payload);
}

TEST_F(CertificateManager, verify_message_modified_generation_time)
{
    // prepare decap request
    security::DecapRequest decap_request = getDecapRequest();

    // iterate through all header_fields
    std::list<security::HeaderField>& header_fields = decap_request.sec_packet.header_fields;
    for (std::list<security::HeaderField>::iterator it = header_fields.begin(); it != header_fields.end(); ++it) {
        // modify generation time
        if (security::HeaderFieldType::Generation_Time == get_type(*it)) {
            security::Time64& generation_time = boost::get<security::Time64>(*it);
            generation_time = 1988711;
        }
    }

    // verify message
    security::DecapConfirm decap_confirm = cert_manager.verify_message(decap_request);
    // check if verify was successful
    EXPECT_EQ(security::ReportType::False_Signature, decap_confirm.report);
}

TEST_F(CertificateManager, verify_message_modified_message_type)
{
    // prepare decap request
    security::DecapRequest decap_request = getDecapRequest();

    // iterate through all header_fields
    std::list<security::HeaderField>& header_fields = decap_request.sec_packet.header_fields;
    for (std::list<security::HeaderField>::iterator it = header_fields.begin(); it != header_fields.end(); ++it) {
        // modify message type
        if (security::HeaderFieldType::Message_Type == get_type(*it)) {
            uint16_t& its_aid = boost::get<uint16_t>(*it);
            its_aid = 42;
        }
    }

    // verify message
    security::DecapConfirm decap_confirm = cert_manager.verify_message(decap_request);
    // check if verify was successful
    EXPECT_EQ(security::ReportType::False_Signature, decap_confirm.report);
}

TEST_F(CertificateManager, verify_message_modified_certificate_signer_info)
{
    // create decap request
    security::DecapRequest decap_request = getDecapRequest();

    // iterate through all header_fields
    auto& header_fields = decap_request.sec_packet.header_fields;
    for (auto& field : header_fields) {
        // modify certificate
        if (security::HeaderFieldType::Signer_Info == get_type(field)) {
            security::SignerInfo& signer_info = boost::get<security::SignerInfo>(field);
            security::Certificate& certificate = boost::get<security::Certificate>(signer_info);

            // change the subject info
            security::HashedId8 faulty_hash { 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88 };
            certificate.signer_info = faulty_hash;
        }
    }

    // verify message
    security::DecapConfirm decap_confirm = cert_manager.verify_message(decap_request);
    // check if verify indicates invalid certificate
    EXPECT_EQ(security::ReportType::Invalid_Certificate, decap_confirm.report);
}

TEST_F(CertificateManager, verify_message_modified_certificate_subject_info)
{
    // create decap request
    security::DecapRequest decap_request = getDecapRequest();

    // iterate through all header_fields
    auto& header_fields = decap_request.sec_packet.header_fields;
    for (auto& field : header_fields) {
        // modify certificate
        if (security::HeaderFieldType::Signer_Info == get_type(field)) {
            security::SignerInfo& signer_info = boost::get<security::SignerInfo>(field);
            security::Certificate& certificate = boost::get<security::Certificate>(signer_info);

            // change the subject info
            certificate.subject_info.subject_type = security::SubjectType::Root_Ca;
        }
    }

    // verify message
    security::DecapConfirm decap_confirm = cert_manager.verify_message(decap_request);
    // check if verify indicates invalid certificate
    EXPECT_EQ(security::ReportType::Invalid_Certificate, decap_confirm.report);
}

TEST_F(CertificateManager, verify_message_modified_certificate_subject_assurance)
{
    // create decap request
    security::DecapRequest decap_request = getDecapRequest();

    // iterate through all header_fields
    auto& header_fields = decap_request.sec_packet.header_fields;
    for (auto& field : header_fields) {
        // modify certificate
        if (security::HeaderFieldType::Signer_Info == get_type(field)) {
            security::SignerInfo& signer_info = boost::get<security::SignerInfo>(field);
            security::Certificate& certificate = boost::get<security::Certificate>(signer_info);

            std::list<security::SubjectAttribute>& subject_attributes_list = certificate.subject_attributes;

            // iterate over subject_attribute list
            for (auto& subject_attribute : subject_attributes_list) {

                if (security::SubjectAttributeType::Assurance_Level == get_type(subject_attribute)) {
                    security::SubjectAssurance& subject_assurance = boost::get<security::SubjectAssurance>(subject_attribute);

                    // change raw in subject assurance to random value
                    subject_assurance.raw = 0x47;
                }
            }
        }
    }

    // verify message
    security::DecapConfirm decap_confirm = cert_manager.verify_message(decap_request);
    // check if verify indicates invalid certificate
    EXPECT_EQ(security::ReportType::Invalid_Certificate, decap_confirm.report);
}

TEST_F(CertificateManager, verify_message_outdated_certificate)
{
    // prepare decap request
    security::DecapRequest decap_request = getDecapRequest();

    // set new value for Timestamp
    time_now += 3000000 * geonet::Timestamp::millisecond;

    // verify message
    security::DecapConfirm decap_confirm = cert_manager.verify_message(decap_request);
    // check if verify indicates invalid certificate
    EXPECT_EQ(security::ReportType::Invalid_Certificate, decap_confirm.report);
}

TEST_F(CertificateManager, verify_message_premature_certificate)
{
    // random offset
    auto time_offset = 1000 * 1000 * geonet::Timestamp::millisecond;

    // add offset to time_now
    time_now += time_offset;

    security::CertificateManager cert_past (time_now);

    // subtract offset from time_now
    time_now -= time_offset;

    // prepare decap request
    // sign message
    security::EncapConfirm encap_confirm = cert_past.sign_message(encap_request);

    // prepare secured message
    security::SecuredMessage secured_message = encap_confirm.sec_packet;

    // prepare decap request
    security::DecapRequest decap_request;
    decap_request.sec_pdu = encap_request.plaintext_pdu;
    decap_request.sec_packet = secured_message;

    // verify message
    security::DecapConfirm decap_confirm = cert_past.verify_message(decap_request);
    // check if verify indicates invalid certificate
    EXPECT_EQ(security::ReportType::Invalid_Certificate, decap_confirm.report);
}

TEST_F(CertificateManager, verify_message_modified_certificate_validity_restriction)
{
    // prepare decap request
    security::DecapRequest decap_request = getDecapRequest();

    // iterate through all header_fields
    auto& header_fields = decap_request.sec_packet.header_fields;
    for (auto& field : header_fields) {
        // modify certificate
        if (security::HeaderFieldType::Signer_Info == get_type(field)) {
            security::SignerInfo& signer_info = boost::get<security::SignerInfo>(field);
            security::Certificate& certificate = boost::get<security::Certificate>(signer_info);

            std::list<security::ValidityRestriction>& restriction_list = certificate.validity_restriction;

            // iterate over validity_restriction list
            for (auto& validity_restriction : restriction_list) {

                security::ValidityRestrictionType type = get_type(validity_restriction);
                ASSERT_EQ(type, security::ValidityRestrictionType::Time_Start_And_End);

                // change start and end time of certificate validity
                security::StartAndEndValidity& start_and_end = boost::get<security::StartAndEndValidity>(validity_restriction);
                start_and_end.start_validity = 500;
                start_and_end.end_validity = 373;
            }
        }
    }

    // verify message
    security::DecapConfirm decap_confirm = cert_manager.verify_message(decap_request);
    // check if verify indicates invalid certificate
    EXPECT_EQ(security::ReportType::Invalid_Certificate, decap_confirm.report);
}

TEST_F(CertificateManager, verify_message_modified_certificate_signature)
{
    // prepare decap request
    security::DecapRequest decap_request = getDecapRequest();

    // iterate through all header_fields
    auto& header_fields = decap_request.sec_packet.header_fields;
    for (auto& field : header_fields) {
        // modify certificate
        if (security::HeaderFieldType::Signer_Info == get_type(field)) {
            security::SignerInfo& signer_info = boost::get<security::SignerInfo>(field);
            security::Certificate& certificate = boost::get<security::Certificate>(signer_info);
            certificate.signature = security::create_random_ecdsa_signature(0);
        }
    }

    // verify message
    security::DecapConfirm decap_confirm = cert_manager.verify_message(decap_request);
    // check if verify indicates invalid certificate
    EXPECT_EQ(security::ReportType::Invalid_Certificate, decap_confirm.report);
}

TEST_F(CertificateManager, verify_message_modified_signature)
{
    // prepare decap request
    security::DecapRequest decap_request = getDecapRequest();

    // iterate through all header_fields
    std::list<security::TrailerField>& trailer_fields = decap_request.sec_packet.trailer_fields;
    for (std::list<security::TrailerField>::iterator it = trailer_fields.begin(); it != trailer_fields.end(); ++it) {
        // modify signature
        if (security::TrailerFieldType::Signature == get_type(*it)) {
            ASSERT_EQ(security::PublicKeyAlgorithm::Ecdsa_Nistp256_With_Sha256, get_type(boost::get<security::Signature>(*it)));
            security::EcdsaSignature& signature = boost::get<security::EcdsaSignature>(boost::get<security::Signature>(*it));
            signature.s = {8, 15, 23};
        }
    }

    // verify message
    security::DecapConfirm decap_confirm = cert_manager.verify_message(decap_request);
    // check if verify was successful
    EXPECT_EQ(security::ReportType::False_Signature, decap_confirm.report);
}

TEST_F(CertificateManager, verify_message_modified_payload_type)
{
    // prepare decap request
    security::DecapRequest decap_request = getDecapRequest();

    // modify payload type
    decap_request.sec_packet.payload.type = security::PayloadType::Encrypted;

    // verify message
    security::DecapConfirm decap_confirm = cert_manager.verify_message(decap_request);
    // check if verify was successful
    EXPECT_EQ(security::ReportType::False_Signature, decap_confirm.report);
}

TEST_F(CertificateManager, verify_message_modified_payload)
{
    // prepare decap request
    security::DecapRequest decap_request = getDecapRequest();

    // modify payload buffer
    decap_request.sec_packet.payload.buffer = {42, 42, 42};

    // verify message
    security::DecapConfirm decap_confirm = cert_manager.verify_message(decap_request);
    // check if verify was successful
    EXPECT_EQ(security::ReportType::False_Signature, decap_confirm.report);
}
