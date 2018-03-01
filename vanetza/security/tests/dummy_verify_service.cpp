#include <gtest/gtest.h>
#include <vanetza/security/verify_service.hpp>

using namespace vanetza::security;

TEST(DummyVerifyServiceTest, lookup)
{
    VerifyService dummy = dummy_verify_service(VerificationReport::Invalid_Timestamp, CertificateValidity::valid());

    SecuredMessageV2 message;
    VerifyRequest req(message);

    auto confirm = dummy(std::move(req));

    EXPECT_EQ(VerificationReport::Invalid_Timestamp, confirm.report);
    EXPECT_TRUE(confirm.certificate_validity);
    EXPECT_EQ(0, confirm.its_aid);
    EXPECT_EQ(vanetza::ByteBuffer({}), confirm.permissions);
}
