#include <gtest/gtest.h>
#include <vanetza/security/verify_service.hpp>
#include <memory>

using namespace vanetza::security;

TEST(DummyVerifyServiceTest, lookup)
{
    std::unique_ptr<VerifyService> dummy { new DummyVerifyService {
        VerificationReport::Invalid_Timestamp, CertificateValidity::valid() }};

    SecuredMessage message;
    VerifyRequest req(&message);

    auto confirm = dummy->verify(std::move(req));

    EXPECT_EQ(VerificationReport::Invalid_Timestamp, confirm.report);
    EXPECT_TRUE(confirm.certificate_validity);
    EXPECT_EQ(0, confirm.its_aid);
    EXPECT_EQ(vanetza::ByteBuffer({}), confirm.permissions);
}
