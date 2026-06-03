#include "certificate_trust_list.hpp"
#include "ctl_test_fixture.hpp"
#include "hashed_id8.hpp"
#include "mock_credential_storage.hpp"
#include "openssl_security_module.hpp"
#include "stub_certificate.hpp"
#include <gtest/gtest.h>
#include <memory>

namespace vanetza
{
namespace pki
{

class CertificateTrustListTest : public ::testing::Test
{
protected:
    CertificateTrustListTest() :
        m_credentials(std::make_shared<MockCredentialStorage>()),
        m_security(std::make_shared<OpenSslSecurityModule>(m_credentials))
    {
    }

    std::shared_ptr<MockCredentialStorage> m_credentials;
    std::shared_ptr<OpenSslSecurityModule> m_security;
};

TEST_F(CertificateTrustListTest, is_full_ctl_true_for_full)
{
    HashedId8 issuer = make_id(0xAB);
    auto ctl = TestRcaCtlBuilder(issuer, true, 5).build();
    auto is_full = ctl.is_full_ctl();
    ASSERT_TRUE(is_full);
    EXPECT_TRUE(*is_full);
}

TEST_F(CertificateTrustListTest, is_full_ctl_false_for_delta)
{
    HashedId8 issuer = make_id(0xAB);
    auto ctl = TestRcaCtlBuilder(issuer, false, 6).build();
    auto is_full = ctl.is_full_ctl();
    ASSERT_TRUE(is_full);
    EXPECT_FALSE(*is_full);
}

TEST_F(CertificateTrustListTest, ctl_sequence_returns_value)
{
    HashedId8 issuer = make_id(0xAB);
    auto ctl = TestRcaCtlBuilder(issuer, true, 42).build();
    auto seq = ctl.ctl_sequence();
    ASSERT_TRUE(seq);
    EXPECT_EQ(42u, *seq);
}

TEST_F(CertificateTrustListTest, get_hashed_id8_matches_signer)
{
    HashedId8 issuer = make_id(0xAB);
    auto ctl = TestRcaCtlBuilder(issuer, true, 1).build();
    auto got = ctl.get_hashed_id8(*m_security);
    ASSERT_TRUE(got);
    EXPECT_EQ(issuer, *got);
}

TEST_F(CertificateTrustListTest, processor_records_aa_from_full_ctl)
{
    HashedId8 issuer = make_id(0xAB);
    PublicKey aa_key = m_security->create_key(KeyType::NistP256);
    auto ctl = TestRcaCtlBuilder(issuer, true, 1).add_aa(aa_key, "https://aa.example/v1").build();

    CertificateTrustListProcessor processor(m_security);
    processor.process(ctl);

    auto aa = processor.get_authorization_authority(issuer);
    ASSERT_TRUE(aa);
    EXPECT_EQ("https://aa.example/v1", aa->access_point);
}

TEST_F(CertificateTrustListTest, processor_records_ea_from_full_ctl)
{
    HashedId8 issuer = make_id(0xAB);
    PublicKey ea_key = m_security->create_key(KeyType::NistP256);
    auto ctl = TestRcaCtlBuilder(issuer, true, 1).add_ea(ea_key, "https://ea.example/aa").build();

    CertificateTrustListProcessor processor(m_security);
    processor.process(ctl);

    auto ea = processor.get_enrolment_authority(issuer);
    ASSERT_TRUE(ea);
    EXPECT_EQ("https://ea.example/aa", ea->aa_access_point);
}

TEST_F(CertificateTrustListTest, full_ctl_clears_prior_state)
{
    HashedId8 issuer = make_id(0xAB);
    PublicKey key_a = m_security->create_key(KeyType::NistP256);
    PublicKey key_b = m_security->create_key(KeyType::NistP256);

    auto ctl_first = TestRcaCtlBuilder(issuer, true, 1)
                         .add_aa(key_a, "https://aa.example/v1")
                         .add_ea(key_a, "https://ea.example/aa")
                         .build();
    auto ctl_second =
        TestRcaCtlBuilder(issuer, true, 2).add_aa(key_b, "https://aa.example/v2").build(); // No EA in second full CTL

    CertificateTrustListProcessor processor(m_security);
    processor.process(ctl_first);
    ASSERT_TRUE(processor.get_authorization_authority(issuer));
    ASSERT_TRUE(processor.get_enrolment_authority(issuer));

    processor.process(ctl_second);
    auto aa = processor.get_authorization_authority(issuer);
    ASSERT_TRUE(aa);
    EXPECT_EQ("https://aa.example/v2", aa->access_point);
    // EA was in the first full CTL but absent from the second: must be gone.
    EXPECT_FALSE(processor.get_enrolment_authority(issuer));
}

TEST_F(CertificateTrustListTest, delta_ctl_applies_on_top_of_prior_state)
{
    HashedId8 issuer = make_id(0xAB);
    PublicKey ea_key = m_security->create_key(KeyType::NistP256);
    PublicKey aa_key = m_security->create_key(KeyType::NistP256);

    auto full = TestRcaCtlBuilder(issuer, true, 1).add_ea(ea_key, "https://ea.example/aa").build();
    auto delta = TestRcaCtlBuilder(issuer, false, 2).add_aa(aa_key, "https://aa.example/v1").build();

    CertificateTrustListProcessor processor(m_security);
    processor.process(full);
    processor.process(delta);

    // EA from the full CTL must survive — delta does NOT clear.
    EXPECT_TRUE(processor.get_enrolment_authority(issuer));
    // AA was added by the delta.
    EXPECT_TRUE(processor.get_authorization_authority(issuer));
}

TEST_F(CertificateTrustListTest, delta_ctl_can_delete_certificate)
{
    HashedId8 issuer = make_id(0xAB);
    PublicKey aa_key = m_security->create_key(KeyType::NistP256);

    auto full = TestRcaCtlBuilder(issuer, true, 1).add_aa(aa_key, "https://aa.example/v1").build();
    auto delta = TestRcaCtlBuilder(issuer, false, 2)
                     .delete_cert(issuer) // remove the entry keyed by the issuer (the AA bucket)
                     .build();

    CertificateTrustListProcessor processor(m_security);
    processor.process(full);
    ASSERT_TRUE(processor.get_authorization_authority(issuer));

    processor.process(delta);
    EXPECT_FALSE(processor.get_authorization_authority(issuer));
}

TEST_F(CertificateTrustListTest, re_announced_aa_overwrites_previous)
{
    HashedId8 issuer = make_id(0xAB);
    PublicKey key_a = m_security->create_key(KeyType::NistP256);
    PublicKey key_b = m_security->create_key(KeyType::NistP256);

    auto ctl = TestRcaCtlBuilder(issuer, true, 1)
                   .add_aa(key_a, "https://aa.example/v1")
                   .add_aa(key_b, "https://aa.example/v2")
                   .build();

    CertificateTrustListProcessor processor(m_security);
    processor.process(ctl);

    auto aa = processor.get_authorization_authority(issuer);
    ASSERT_TRUE(aa);
    // Last add wins (insert_or_assign).
    EXPECT_EQ("https://aa.example/v2", aa->access_point);
}

TEST_F(CertificateTrustListTest, is_full_ctl_works_for_tlm_ctl)
{
    HashedId8 issuer = make_id(0xCD);
    auto ctl = TestTlmCtlBuilder(issuer, true, 7).build();
    auto is_full = ctl.is_full_ctl();
    ASSERT_TRUE(is_full);
    EXPECT_TRUE(*is_full);
    auto seq = ctl.ctl_sequence();
    ASSERT_TRUE(seq);
    EXPECT_EQ(7u, *seq);
}

TEST_F(CertificateTrustListTest, processor_records_root_ca_from_tlm_ctl)
{
    HashedId8 tlm_issuer = make_id(0xCD);
    PublicKey rca_key = m_security->create_key(KeyType::NistP256);
    auto ectl = TestTlmCtlBuilder(tlm_issuer, true, 1).add_root_ca(rca_key).build();

    CertificateTrustListProcessor processor(m_security);
    processor.process(ectl);

    // The RCA's HashedId8 is computed from the cert itself (not the issuer).
    // Locate it via the same path the processor uses internally.
    Certificate stub = build_stub_certificate(rca_key);
    HashedId8 rca_hid = stub.calculate_hashed_id8(*m_security);

    EXPECT_TRUE(processor.get_root_ca(rca_hid));
}

TEST_F(CertificateTrustListTest, processor_records_tlm_from_tlm_ctl)
{
    HashedId8 tlm_issuer = make_id(0xCD);
    PublicKey tlm_key = m_security->create_key(KeyType::NistP256);
    auto ectl = TestTlmCtlBuilder(tlm_issuer, true, 1).add_tlm(tlm_key, "https://cpoc.example/").build();

    CertificateTrustListProcessor processor(m_security);
    processor.process(ectl);

    Certificate stub = build_stub_certificate(tlm_key);
    HashedId8 tlm_hid = stub.calculate_hashed_id8(*m_security);

    EXPECT_TRUE(processor.get_trust_list_manager(tlm_hid));
}

TEST_F(CertificateTrustListTest, full_tlm_ctl_clears_prior_root_cas)
{
    HashedId8 tlm_issuer = make_id(0xCD);
    PublicKey rca_a_key = m_security->create_key(KeyType::NistP256);
    PublicKey rca_b_key = m_security->create_key(KeyType::NistP256);

    Certificate rca_a_stub = build_stub_certificate(rca_a_key);
    HashedId8 rca_a_hid = rca_a_stub.calculate_hashed_id8(*m_security);

    auto first = TestTlmCtlBuilder(tlm_issuer, true, 1).add_root_ca(rca_a_key).build();
    auto second = TestTlmCtlBuilder(tlm_issuer, true, 2).add_root_ca(rca_b_key).build();

    CertificateTrustListProcessor processor(m_security);
    processor.process(first);
    ASSERT_TRUE(processor.get_root_ca(rca_a_hid));

    processor.process(second);
    // RCA A was in the first full ECTL but absent from the second: must be gone.
    EXPECT_FALSE(processor.get_root_ca(rca_a_hid));
}

TEST_F(CertificateTrustListTest, delta_tlm_ctl_can_delete_root_ca)
{
    HashedId8 tlm_issuer = make_id(0xCD);
    PublicKey rca_key = m_security->create_key(KeyType::NistP256);
    Certificate rca_stub = build_stub_certificate(rca_key);
    HashedId8 rca_hid = rca_stub.calculate_hashed_id8(*m_security);

    auto full = TestTlmCtlBuilder(tlm_issuer, true, 1).add_root_ca(rca_key).build();
    auto delta = TestTlmCtlBuilder(tlm_issuer, false, 2).delete_cert(rca_hid).build();

    CertificateTrustListProcessor processor(m_security);
    processor.process(full);
    ASSERT_TRUE(processor.get_root_ca(rca_hid));

    processor.process(delta);
    EXPECT_FALSE(processor.get_root_ca(rca_hid));
}

} // namespace pki
} // namespace vanetza
