#include <gtest/gtest.h>

#include <vanetza/common/its_aid.hpp>
#include <vanetza/security/verify_service.hpp>
#include <vanetza/security/v3/certificate.hpp>
#include <vanetza/security/v3/certificate_cache.hpp>
#include <vanetza/security/v3/secured_message.hpp>
#include <memory>

using namespace vanetza;
using namespace vanetza::security;

TEST(DummyVerifyServiceTest, lookup)
{
    std::unique_ptr<VerifyService> dummy { new DummyVerifyService {
        VerificationReport::Invalid_Timestamp, CertificateValidity::valid() }};

    SecuredMessage message;
    VerifyRequest req(SecuredMessageView { message });

    auto confirm = dummy->verify(std::move(req));

    EXPECT_EQ(VerificationReport::Invalid_Timestamp, confirm.report);
    EXPECT_TRUE(confirm.certificate_validity);
    EXPECT_EQ(0, confirm.its_aid);
    EXPECT_EQ(vanetza::ByteBuffer({}), confirm.permissions);
    EXPECT_FALSE(confirm.certificate_id);
}

TEST(DummyVerifyServiceTest, signer_with_full_certificate)
{
    DummyVerifyService dummy { VerificationReport::Success, CertificateValidity::valid() };

    v3::Certificate cert = v3::fake_certificate();
    auto digest = cert.calculate_digest();
    ASSERT_TRUE(digest);

    v3::SecuredMessage msg = v3::SecuredMessage::with_signed_data();
    msg.set_its_aid(aid::CA);
    msg.set_signer_identifier(cert);

    auto confirm = dummy.verify(VerifyRequest { SecuredMessageView { std::move(msg) } });

    EXPECT_EQ(aid::CA, confirm.its_aid);
    ASSERT_TRUE(confirm.certificate_id);
    EXPECT_EQ(*digest, *confirm.certificate_id);
    EXPECT_EQ(ByteBuffer({ 1, 0, 0 }), confirm.permissions);
}

TEST(DummyVerifyServiceTest, signer_with_digest_no_cache)
{
    DummyVerifyService dummy { VerificationReport::Success, CertificateValidity::valid() };

    HashedId8 digest = {{ 1, 2, 3, 4, 5, 6, 7, 8 }};
    v3::SecuredMessage msg = v3::SecuredMessage::with_signed_data();
    msg.set_its_aid(aid::CA);
    msg.set_signer_identifier(digest);

    auto confirm = dummy.verify(VerifyRequest { SecuredMessageView { std::move(msg) } });

    ASSERT_TRUE(confirm.certificate_id);
    EXPECT_EQ(digest, *confirm.certificate_id);
    EXPECT_TRUE(confirm.permissions.empty());
}

TEST(DummyVerifyServiceTest, signer_with_digest_cache_hit)
{
    DummyVerifyService dummy { VerificationReport::Success, CertificateValidity::valid() };

    v3::Certificate cert = v3::fake_certificate();
    auto digest = cert.calculate_digest();
    ASSERT_TRUE(digest);
    
    v3::CertificateCache cache;
    cache.store(std::move(cert));
    dummy.use_certificate_cache(&cache);

    v3::SecuredMessage msg = v3::SecuredMessage::with_signed_data();
    msg.set_its_aid(aid::CA);
    msg.set_signer_identifier(*digest);

    auto confirm = dummy.verify(VerifyRequest { SecuredMessageView { std::move(msg) } });

    ASSERT_TRUE(confirm.certificate_id);
    EXPECT_EQ(*digest, *confirm.certificate_id);
    EXPECT_EQ(ByteBuffer({ 1, 0, 0 }), confirm.permissions);
}

TEST(DummyVerifyServiceTest, signer_with_digest_cache_miss)
{
    DummyVerifyService dummy { VerificationReport::Success, CertificateValidity::valid() };

    v3::Certificate cert = v3::fake_certificate();
    auto digest = cert.calculate_digest();
    ASSERT_TRUE(digest);

    v3::CertificateCache cache;
    // certificate is not added
    dummy.use_certificate_cache(&cache);

    v3::SecuredMessage msg = v3::SecuredMessage::with_signed_data();
    msg.set_its_aid(aid::CA);
    msg.set_signer_identifier(*digest);

    auto confirm = dummy.verify(VerifyRequest { SecuredMessageView { std::move(msg) } });

    ASSERT_TRUE(confirm.certificate_id);
    EXPECT_EQ(*digest, *confirm.certificate_id);
    EXPECT_TRUE(confirm.permissions.empty());
}

TEST(DummyVerifyServiceTest, full_certificate_populates_cache)
{
    DummyVerifyService dummy { VerificationReport::Success, CertificateValidity::valid() };

    v3::CertificateCache cache;
    dummy.use_certificate_cache(&cache);

    v3::Certificate cert = v3::fake_certificate();
    auto digest = cert.calculate_digest();
    ASSERT_TRUE(digest);

    v3::SecuredMessage msg = v3::SecuredMessage::with_signed_data();
    msg.set_its_aid(aid::CA);
    msg.set_signer_identifier(cert);

    EXPECT_EQ(nullptr, cache.lookup(*digest));
    auto confirm = dummy.verify(VerifyRequest { SecuredMessageView { std::move(msg) } });

    EXPECT_EQ(ByteBuffer({ 1, 0, 0 }), confirm.permissions);
    EXPECT_EQ(1u, cache.size());
    EXPECT_NE(nullptr, cache.lookup(*digest));
}

TEST(DummyVerifyServiceTest, permissions_empty_for_unrelated_aid)
{
    DummyVerifyService dummy { VerificationReport::Success, CertificateValidity::valid() };

    v3::Certificate cert = v3::fake_certificate();
    auto digest = cert.calculate_digest();
    ASSERT_TRUE(digest);

    v3::SecuredMessage msg = v3::SecuredMessage::with_signed_data();
    msg.set_its_aid(aid::DEN);
    msg.set_signer_identifier(cert);

    auto confirm = dummy.verify(VerifyRequest { SecuredMessageView { std::move(msg) } });

    EXPECT_EQ(aid::DEN, confirm.its_aid);
    ASSERT_TRUE(confirm.certificate_id);
    EXPECT_EQ(*digest, *confirm.certificate_id);
    EXPECT_TRUE(confirm.permissions.empty());
}
