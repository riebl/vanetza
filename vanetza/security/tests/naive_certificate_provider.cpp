#include <vanetza/common/clock.hpp>
#include <vanetza/common/manual_runtime.hpp>
#include <vanetza/security/default_certificate_validator.hpp>
#include <vanetza/security/naive_certificate_provider.hpp>
#include <boost/variant/get.hpp>
#include <gtest/gtest.h>

using namespace vanetza;
using namespace vanetza::security;
using boost::get;

class NaiveCertificateProviderTest : public ::testing::Test
{
public:
    NaiveCertificateProviderTest() : runtime(Clock::at("2016-08-01 00:00")), cert_provider(runtime)
    {
    }

protected:
    ManualRuntime runtime;
    NaiveCertificateProvider cert_provider;
};

TEST_F(NaiveCertificateProviderTest, own_certificate)
{
    Certificate signed_certificate = cert_provider.own_certificate();

    // Check signature
    EXPECT_EQ(2 * field_size(PublicKeyAlgorithm::ECDSA_NISTP256_With_SHA256),
              extract_signature_buffer(signed_certificate.signature).size());
    EXPECT_EQ(PublicKeyAlgorithm::ECDSA_NISTP256_With_SHA256, get_type(signed_certificate.signature));

    // Check signer_info and subject_info
    EXPECT_EQ(2, signed_certificate.version());
    EXPECT_EQ(SignerInfoType::Certificate_Digest_With_SHA256, get_type(signed_certificate.signer_info));
    EXPECT_EQ(SubjectType::Authorization_Ticket, signed_certificate.subject_info.subject_type);
    EXPECT_TRUE(signed_certificate.subject_info.subject_name.empty());

    // Check subject attributes
    int verification_key_counter = 0;
    SubjectAssurance test_assurance_level;
    int assurance_level_counter = 0;

    using subject_type_int = std::underlying_type<SubjectAttributeType>::type;
    subject_type_int last_subject_type = 0;

    for (auto& subject_attribute : signed_certificate.subject_attributes) {
        // Verify that fields are in ascending order
        subject_type_int subject_type = static_cast<subject_type_int>(get_type(subject_attribute));
        EXPECT_LE(last_subject_type, subject_type);
        last_subject_type = subject_type;

        if (SubjectAttributeType::Verification_Key == get_type(subject_attribute)) {
            verification_key_counter++;
        } else if (SubjectAttributeType::Assurance_Level == get_type(subject_attribute)) {
            test_assurance_level = get<SubjectAssurance>(subject_attribute);
            assurance_level_counter++;
        } else if (SubjectAttributeType::ITS_AID_SSP_List == get_type(subject_attribute)) {
            // TODO: check aid permissions
        }
    }

    EXPECT_EQ(1, verification_key_counter);
    ASSERT_EQ(1, assurance_level_counter);
    EXPECT_EQ(0, test_assurance_level.raw);

    // Check validity restrictions
    Time32 start_time;
    Time32 end_time;

    using restriction_type_int = std::underlying_type<ValidityRestrictionType>::type;
    restriction_type_int last_restriction_type = 0;

    for (ValidityRestriction restriction : signed_certificate.validity_restriction) {
        // Verify that fields are in ascending order
        restriction_type_int restriction_type = static_cast<restriction_type_int>(get_type(restriction));
        EXPECT_LE(last_restriction_type, restriction_type);
        last_restriction_type = restriction_type;

        if (ValidityRestrictionType::Time_Start_And_End == get_type(restriction)) {
            StartAndEndValidity& time_validation = get<StartAndEndValidity>(restriction);
            start_time = time_validation.start_validity;
            end_time = time_validation.end_validity;
        } else if (ValidityRestrictionType::Region == get_type(restriction)) {
            // TODO: Region not specified yet
        }
    }

    EXPECT_LT(start_time, end_time);
}
