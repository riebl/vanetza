#include <vanetza/asn1/asn1c_wrapper.hpp>
#include <vanetza/common/its_aid.hpp>
#include <vanetza/security/crypto_provider.hpp>
#include <vanetza/security/memory_credential_storage.hpp>
#include <vanetza/security/security_module.hpp>
#include <vanetza/security/v3/hash.hpp>
#include <vanetza/security/v3/naive_credential_provider.hpp>
#if defined VANETZA_WITH_OPENSSL
#   include <vanetza/security/openssl_security_module.hpp>
#elif defined VANETZA_WITH_CRYPTOPP
#   include <vanetza/security/cryptopp_security_module.hpp>
#endif
#include <gtest/gtest.h>
#include <chrono>
#include <memory>

using namespace vanetza;
using namespace vanetza::security;
using namespace vanetza::security::v3;

class NaiveCredentialProviderTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        if (!crypto || !module) {
            GTEST_SKIP() << "no crypto provider or security module built in";
        }
    }

    // provider with certificates issued now
    std::unique_ptr<NaiveCredentialProvider> issued_provider(SecurityModule& security)
    {
        auto provider = std::make_unique<NaiveCredentialProvider>(security, *crypto);
        const std::error_code error = provider->issue_certificates(now);
        EXPECT_FALSE(error) << error.message();
        return error ? nullptr : std::move(provider);
    }

    // signature of subject verifies with public key of signer
    bool verifies(const Certificate& subject, const ByteBuffer& hash, const Certificate& signer)
    {
        const boost::optional<PublicKey> key = get_public_key(*signer.content());
        const boost::optional<Signature> signature = get_signature(*subject.content());
        if (!key || !signature) {
            return false;
        }
        const expected<bool> verified = verify_hash(*crypto, HashAlgorithm::SHA256, hash, *signature, *key);
        return verified.has_value() && *verified;
    }

    // subject names issuer by its digest and carries its signature
    bool issued_by(const Certificate& subject, const Certificate& issuer)
    {
        const ByteBuffer hash = calculate_certificate_hash(*crypto, HashAlgorithm::SHA256, subject, issuer);
        return subject.issuer_digest() == issuer.calculate_digest(*crypto) && verifies(subject, hash, issuer);
    }

    // IEEE 1609.2 clause 5.3.1.2.2: self-signed certificates hash an empty signer input
    bool self_signed(const Certificate& certificate)
    {
        const boost::optional<Certificate> canonical = certificate.canonicalize();
        if (!canonical || !certificate.issuer_is_self()) {
            return false;
        }
        const ByteBuffer tbs = vanetza::asn1::encode_oer(
            asn_DEF_Vanetza_Security_ToBeSignedCertificate, &canonical->content()->toBeSigned);
        ByteBuffer concatenated = calculate_hash(*crypto, HashAlgorithm::SHA256, tbs);
        const ByteBuffer signer = calculate_hash(*crypto, HashAlgorithm::SHA256, ByteBuffer {});
        concatenated.insert(concatenated.end(), signer.begin(), signer.end());
        const ByteBuffer hash = calculate_hash(*crypto, HashAlgorithm::SHA256, concatenated);
        return verifies(certificate, hash, certificate);
    }

    const Clock::time_point now = Clock::at("2026-11-15 12:00");
    std::unique_ptr<CryptoProvider> crypto = create_crypto_provider();
    std::unique_ptr<SecurityModule> module = create_security_module();
};

TEST_F(NaiveCredentialProviderTest, no_credential_before_issue)
{
    NaiveCredentialProvider provider { *module, *crypto };
    EXPECT_FALSE(provider.signing_credential(aid::CA));
    EXPECT_FALSE(provider.aa_certificate());
    EXPECT_FALSE(provider.root_certificate());
}

TEST_F(NaiveCredentialProviderTest, root_is_self_signed)
{
    std::unique_ptr<NaiveCredentialProvider> provider = issued_provider(*module);
    ASSERT_TRUE(provider);
    EXPECT_TRUE(self_signed(*provider->root_certificate()));
}

TEST_F(NaiveCredentialProviderTest, aa_is_issued_by_root)
{
    std::unique_ptr<NaiveCredentialProvider> provider = issued_provider(*module);
    ASSERT_TRUE(provider);
    EXPECT_TRUE(issued_by(*provider->aa_certificate(), *provider->root_certificate()));
}

TEST_F(NaiveCredentialProviderTest, ticket_is_issued_by_aa)
{
    std::unique_ptr<NaiveCredentialProvider> provider = issued_provider(*module);
    ASSERT_TRUE(provider);
    const Credential* credential = provider->signing_credential(aid::CA);
    ASSERT_TRUE(credential);
    EXPECT_TRUE(issued_by(credential->certificate, *provider->aa_certificate()));
}

TEST_F(NaiveCredentialProviderTest, credential_key_belongs_to_ticket)
{
    std::unique_ptr<NaiveCredentialProvider> provider = issued_provider(*module);
    ASSERT_TRUE(provider);
    const Credential* credential = provider->signing_credential(aid::CA);
    ASSERT_TRUE(credential);
    const expected<PublicKey> key = module->public_key(credential->key);
    ASSERT_TRUE(key.has_value());
    const boost::optional<PublicKey> ticket_key = get_public_key(*credential->certificate.content());
    ASSERT_TRUE(ticket_key);
    EXPECT_EQ(canonical_hexstring(*ticket_key), canonical_hexstring(*key));
}

TEST_F(NaiveCredentialProviderTest, credential_requires_permitted_aid)
{
    std::unique_ptr<NaiveCredentialProvider> provider = issued_provider(*module);
    ASSERT_TRUE(provider);
    EXPECT_TRUE(provider->signing_credential(aid::DEN));
    EXPECT_FALSE(provider->signing_credential(aid::TLM));
}

TEST_F(NaiveCredentialProviderTest, chain_is_valid_at_creation)
{
    std::unique_ptr<NaiveCredentialProvider> provider = issued_provider(*module);
    ASSERT_TRUE(provider);
    const Credential* credential = provider->signing_credential(aid::CA);
    ASSERT_TRUE(credential);
    EXPECT_TRUE(credential->certificate.valid_at_timepoint(now));
    EXPECT_TRUE(provider->aa_certificate()->valid_at_timepoint(now));
    EXPECT_TRUE(provider->root_certificate()->valid_at_timepoint(now));
}

TEST_F(NaiveCredentialProviderTest, later_issue_renews_ticket_only)
{
    std::unique_ptr<NaiveCredentialProvider> provider = issued_provider(*module);
    ASSERT_TRUE(provider);
    const Certificate created = provider->signing_credential(aid::CA)->certificate;
    const Certificate aa_certificate = *provider->aa_certificate();
    const Certificate root_certificate = *provider->root_certificate();

    const Clock::time_point later = now + std::chrono::hours(22);
    ASSERT_FALSE(provider->issue_certificates(later));
    const Credential* renewed = provider->signing_credential(aid::CA);
    ASSERT_TRUE(renewed);
    EXPECT_TRUE(renewed->certificate.valid_at_timepoint(later + std::chrono::hours(21)));
    EXPECT_TRUE(issued_by(renewed->certificate, *provider->aa_certificate()));
    EXPECT_EQ(canonical_hexstring(*get_public_key(*created.content())),
        canonical_hexstring(*get_public_key(*renewed->certificate.content())));
    EXPECT_EQ(aa_certificate.encode(), provider->aa_certificate()->encode());
    EXPECT_EQ(root_certificate.encode(), provider->root_certificate()->encode());
}

#if defined VANETZA_WITH_OPENSSL || defined VANETZA_WITH_CRYPTOPP
TEST_F(NaiveCredentialProviderTest, keys_are_discarded_with_provider)
{
    // a module storing its keys reveals the keys not discarded yet
    struct CountingVisitor : public CredentialVisitor
    {
        void visit(const std::string&) override { ++count; }
        std::size_t count = 0;
    };
    auto storage = std::make_shared<MemoryCredentialStorage>();
#if defined VANETZA_WITH_OPENSSL
    OpenSslSecurityModule storing { storage };
#else
    CryptoppSecurityModule storing { storage };
#endif

    std::unique_ptr<NaiveCredentialProvider> provider = issued_provider(storing);
    ASSERT_TRUE(provider);
    CountingVisitor created;
    ASSERT_FALSE(storage->visit(created));
    EXPECT_EQ(3u, created.count);

    provider.reset();
    CountingVisitor remaining;
    ASSERT_FALSE(storage->visit(remaining));
    EXPECT_EQ(0u, remaining.count);
}
#endif
