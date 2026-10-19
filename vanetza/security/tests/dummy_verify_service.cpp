#include <gtest/gtest.h>

#include <vanetza/common/byte_sequence.hpp>
#include <vanetza/common/its_aid.hpp>
#include <vanetza/common/manual_runtime.hpp>
#include <vanetza/security/verify_service.hpp>
#include <vanetza/security/v2/certificate.hpp>
#include <vanetza/security/v2/certificate_cache.hpp>
#include <vanetza/security/v2/secured_message.hpp>
#include <vanetza/security/v3/certificate.hpp>
#include <vanetza/security/v3/certificate_cache.hpp>
#include <vanetza/security/v3/secured_message.hpp>
#include <memory>

using namespace vanetza;
using namespace vanetza::security;

// v2 certificate with a well-formed (but meaningless) signature, so it can be hashed
static v2::Certificate create_v2_certificate(int seed, v2::SubjectType type = v2::SubjectType::Authorization_Ticket)
{
    const std::size_t field = v2::field_size(v2::PublicKeyAlgorithm::ECDSA_NISTP256_With_SHA256);
    EcdsaSignature signature;
    signature.s = random_byte_sequence(field, seed);
    signature.R = X_Coordinate_Only { random_byte_sequence(field, ~seed) };

    v2::Certificate cert;
    cert.subject_info.subject_type = type;
    cert.signature = signature;
    return cert;
}

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

TEST(DummyVerifyServiceTest, v2_signer_with_full_certificate)
{
    DummyVerifyService dummy { VerificationReport::Invalid_Timestamp, CertificateValidity::valid() };

    v2::Certificate cert = create_v2_certificate(1);
    cert.add_permission(aid::CA, ByteBuffer({ 1, 0, 0 }));
    cert.add_permission(aid::DEN, ByteBuffer({ 2 }));

    v2::SecuredMessage msg;
    msg.header_fields.push_back(v2::IntX { aid::CA });
    msg.header_fields.push_back(v2::SignerInfo { cert });

    auto confirm = dummy.verify(VerifyRequest { SecuredMessageView { std::move(msg) } });

    EXPECT_EQ(VerificationReport::Invalid_Timestamp, confirm.report);
    EXPECT_EQ(aid::CA, confirm.its_aid);
    ASSERT_TRUE(confirm.certificate_id);
    EXPECT_EQ(v2::calculate_hash(cert), *confirm.certificate_id);
    EXPECT_EQ(ByteBuffer({ 1, 0, 0 }), confirm.permissions);
}

TEST(DummyVerifyServiceTest, v2_signer_with_digest)
{
    DummyVerifyService dummy { VerificationReport::Success, CertificateValidity::valid() };

    HashedId8 digest = {{ 8, 7, 6, 5, 4, 3, 2, 1 }};
    v2::SecuredMessage msg;
    msg.header_fields.push_back(v2::IntX { aid::CA });
    msg.header_fields.push_back(v2::SignerInfo { digest });

    auto confirm = dummy.verify(VerifyRequest { SecuredMessageView { std::move(msg) } });

    ASSERT_TRUE(confirm.certificate_id);
    EXPECT_EQ(digest, *confirm.certificate_id);
    EXPECT_TRUE(confirm.permissions.empty());
}

TEST(DummyVerifyServiceTest, v2_signer_with_certificate_chain)
{
    DummyVerifyService dummy { VerificationReport::Success, CertificateValidity::valid() };

    v2::Certificate authority = create_v2_certificate(2, v2::SubjectType::Authorization_Authority);
    authority.add_permission(aid::CA, ByteBuffer({ 9, 9, 9 }));
    v2::Certificate ticket = create_v2_certificate(3);
    ticket.add_permission(aid::CA, ByteBuffer({ 1, 0, 0 }));

    v2::SecuredMessage msg;
    msg.header_fields.push_back(v2::IntX { aid::CA });
    msg.header_fields.push_back(v2::SignerInfo { std::list<v2::Certificate> { authority, ticket } });

    auto confirm = dummy.verify(VerifyRequest { SecuredMessageView { std::move(msg) } });

    // last certificate in chain is the signer
    ASSERT_TRUE(confirm.certificate_id);
    EXPECT_EQ(v2::calculate_hash(ticket), *confirm.certificate_id);
    EXPECT_EQ(ByteBuffer({ 1, 0, 0 }), confirm.permissions);
}

TEST(DummyVerifyServiceTest, v2_without_signer_info)
{
    DummyVerifyService dummy { VerificationReport::Success, CertificateValidity::valid() };

    v2::SecuredMessage msg;
    msg.header_fields.push_back(v2::IntX { aid::CA });

    auto confirm = dummy.verify(VerifyRequest { SecuredMessageView { std::move(msg) } });

    EXPECT_EQ(VerificationReport::Success, confirm.report);
    EXPECT_EQ(aid::CA, confirm.its_aid);
    EXPECT_FALSE(confirm.certificate_id);
    EXPECT_TRUE(confirm.permissions.empty());
}

TEST(DummyVerifyServiceTest, v2_signer_with_digest_cache_miss)
{
    DummyVerifyService dummy { VerificationReport::Success, CertificateValidity::valid() };

    ManualRuntime runtime;
    v2::CertificateCache cache(runtime);
    // certificate is not added
    dummy.use_certificate_cache(&cache);

    const HashedId8 digest = {{ 8, 7, 6, 5, 4, 3, 2, 1 }};
    v2::SecuredMessage msg;
    msg.header_fields.push_back(v2::IntX { aid::CA });
    msg.header_fields.push_back(v2::SignerInfo { digest });

    auto confirm = dummy.verify(VerifyRequest { SecuredMessageView { std::move(msg) } });

    ASSERT_TRUE(confirm.certificate_id);
    EXPECT_EQ(digest, *confirm.certificate_id);
    EXPECT_TRUE(confirm.permissions.empty());
    EXPECT_EQ(0, cache.size());
}

TEST(DummyVerifyServiceTest, v2_full_certificate_populates_cache)
{
    DummyVerifyService dummy { VerificationReport::Success, CertificateValidity::valid() };

    ManualRuntime runtime;
    v2::CertificateCache cache(runtime);
    dummy.use_certificate_cache(&cache);

    v2::Certificate cert = create_v2_certificate(1);
    cert.add_permission(aid::CA, ByteBuffer({ 1, 0, 0 }));
    const HashedId8 digest = v2::calculate_hash(cert);

    v2::SecuredMessage with_cert;
    with_cert.header_fields.push_back(v2::IntX { aid::CA });
    with_cert.header_fields.push_back(v2::SignerInfo { cert });
    dummy.verify(VerifyRequest { SecuredMessageView { std::move(with_cert) } });
    EXPECT_EQ(1, cache.size());

    // subsequent message refers to certificate by digest only
    v2::SecuredMessage with_digest;
    with_digest.header_fields.push_back(v2::IntX { aid::CA });
    with_digest.header_fields.push_back(v2::SignerInfo { digest });
    auto confirm = dummy.verify(VerifyRequest { SecuredMessageView { std::move(with_digest) } });

    ASSERT_TRUE(confirm.certificate_id);
    EXPECT_EQ(digest, *confirm.certificate_id);
    EXPECT_EQ(ByteBuffer({ 1, 0, 0 }), confirm.permissions);
}

TEST(DummyVerifyServiceTest, v2_certificate_chain_populates_cache_with_signer)
{
    DummyVerifyService dummy { VerificationReport::Success, CertificateValidity::valid() };

    ManualRuntime runtime;
    v2::CertificateCache cache(runtime);
    dummy.use_certificate_cache(&cache);

    v2::Certificate authority = create_v2_certificate(2, v2::SubjectType::Authorization_Authority);
    v2::Certificate ticket = create_v2_certificate(3);
    ticket.add_permission(aid::CA, ByteBuffer({ 1, 0, 0 }));

    v2::SecuredMessage with_chain;
    with_chain.header_fields.push_back(v2::IntX { aid::CA });
    with_chain.header_fields.push_back(v2::SignerInfo { std::list<v2::Certificate> { authority, ticket } });
    dummy.verify(VerifyRequest { SecuredMessageView { std::move(with_chain) } });

    // only the signing ticket is remembered, its issuer is of no use to the dummy
    EXPECT_EQ(1, cache.size());
    EXPECT_EQ(0, cache.lookup(v2::calculate_hash(authority), v2::SubjectType::Authorization_Authority).size());
    EXPECT_EQ(1, cache.lookup(v2::calculate_hash(ticket), v2::SubjectType::Authorization_Ticket).size());
}

TEST(DummyVerifyServiceTest, v2_other_algorithm_digest_skips_cache)
{
    DummyVerifyService dummy { VerificationReport::Success, CertificateValidity::valid() };

    v2::Certificate cert = create_v2_certificate(1);
    cert.add_permission(aid::CA, ByteBuffer({ 1, 0, 0 }));

    ManualRuntime runtime;
    v2::CertificateCache cache(runtime);
    cache.insert(cert);
    dummy.use_certificate_cache(&cache);

    // cache keys are SHA-256 hashes, a digest of another algorithm must not match
    v2::CertificateDigestWithOtherAlgorithm other;
    other.algorithm = v2::PublicKeyAlgorithm::ECIES_NISTP256;
    other.digest = v2::calculate_hash(cert);

    v2::SecuredMessage msg;
    msg.header_fields.push_back(v2::IntX { aid::CA });
    msg.header_fields.push_back(v2::SignerInfo { other });

    auto confirm = dummy.verify(VerifyRequest { SecuredMessageView { std::move(msg) } });

    ASSERT_TRUE(confirm.certificate_id);
    EXPECT_EQ(other.digest, *confirm.certificate_id);
    EXPECT_TRUE(confirm.permissions.empty());
}
