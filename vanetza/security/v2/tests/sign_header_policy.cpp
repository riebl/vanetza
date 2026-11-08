#include <vanetza/common/its_aid.hpp>
#include <vanetza/common/manual_runtime.hpp>
#include <vanetza/common/stored_position_provider.hpp>
#include <vanetza/security/sign_service.hpp>
#include <vanetza/security/v2/certificate.hpp>
#include <vanetza/security/v2/credential_provider.hpp>
#include <vanetza/security/v2/sign_header_policy.hpp>
#include <boost/variant/get.hpp>
#include <gtest/gtest.h>

using namespace vanetza;
using namespace vanetza::security;
using namespace vanetza::security::v2;

namespace
{

Certificate make_certificate(SubjectType type)
{
    Certificate certificate;
    certificate.subject_info.subject_type = type;
    // calculate_hash serializes the signature, its r and s need 32 octets (NIST P-256)
    certificate.signature = EcdsaSignature { X_Coordinate_Only { ByteBuffer(32, 0x00) }, ByteBuffer(32, 0x00) };
    return certificate;
}

} // namespace

class SignHeaderPolicyV2Test : public ::testing::Test
{
protected:
    void SetUp() override
    {
        // the first CAM carries the full certificate anyway
        next_cam_signer();
    }

    // signer info of a CAM within a second after the previous CAM, i.e. the ticket's digest unless requested otherwise
    SignerInfo next_cam_signer()
    {
        SignRequest request;
        request.its_aid = aid::CA;
        for (const HeaderField& field : policy.prepare_header(request, credential)) {
            if (get_type(field) == HeaderFieldType::Signer_Info) {
                return boost::get<SignerInfo>(field);
            }
        }
        ADD_FAILURE() << "CAM header without signer info";
        return nullptr;
    }

    ManualRuntime runtime { Clock::at("2024-08-12 11:30") };
    StoredPositionProvider positioning;
    DefaultSignHeaderPolicy policy { runtime, positioning };
    const Certificate ticket = make_certificate(SubjectType::Authorization_Ticket);
    const Certificate authority = make_certificate(SubjectType::Authorization_Authority);
    const Credential credential { ticket, authority, KeyReference {} };
};

TEST_F(SignHeaderPolicyV2Test, requested_ticket_is_signer_of_next_cam)
{
    policy.report_certificate_request(truncate(calculate_hash(ticket)));
    EXPECT_EQ(SignerInfoType::Certificate, get_type(next_cam_signer()));
}

TEST_F(SignHeaderPolicyV2Test, requested_authority_puts_chain_into_next_cam)
{
    policy.report_certificate_request(truncate(calculate_hash(authority)));
    EXPECT_EQ(SignerInfoType::Certificate_Chain, get_type(next_cam_signer()));
}

TEST_F(SignHeaderPolicyV2Test, request_of_foreign_certificate_is_ignored)
{
    policy.report_certificate_request(truncate(calculate_hash(make_certificate(SubjectType::Root_CA))));
    EXPECT_EQ(SignerInfoType::Certificate_Digest_With_SHA256, get_type(next_cam_signer()));
}
