#include <vanetza/common/its_aid.hpp>
#include <vanetza/security/crypto_provider.hpp>
#include <vanetza/security/memory_credential_storage.hpp>
#include <vanetza/security/security_module.hpp>
#include <vanetza/security/tests/implementations.hpp>
#include <vanetza/security/v2/naive_credential_provider.hpp>
#include <vanetza/security/v2/signature.hpp>
#include <gtest/gtest.h>
#include <chrono>
#include <memory>
#include <string>
#include <vector>

using namespace vanetza;
using namespace vanetza::security;
using namespace vanetza::security::v2;

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

    // signature of SHA-256 digest of subject verifies with public key of signer (TS 103 097 v1.2.1, clause 7.4)
    bool verifies(const Certificate& subject, const Certificate& signer)
    {
        const boost::optional<security::PublicKey> key = get_verification_key(signer);
        const boost::optional<EcdsaSignature> ecdsa = extract_ecdsa_signature(subject.signature);
        if (!key || !ecdsa) {
            return false;
        }
        const ByteBuffer data = convert_for_signing(subject);
        const Sha256Hash digest = crypto->calculate_sha256_hash(data.data(), data.size());
        const security::Signature signature { convert_for_signing(ecdsa->R), ecdsa->s, KeyType::NistP256 };
        const expected<bool> verified = crypto->verify(digest, signature, *key);
        return verified.has_value() && *verified;
    }

    // subject names issuer by its digest and carries its signature
    bool issued_by(const Certificate& subject, const Certificate& issuer)
    {
        const HashedId8* digest = boost::get<HashedId8>(&subject.signer_info);
        return digest && *digest == calculate_hash(*crypto, issuer) && verifies(subject, issuer);
    }

    // validity period of certificate covers the time
    bool valid_at(const Certificate& certificate, Clock::time_point time)
    {
        const StartAndEndValidity* validity =
            certificate.get_restriction<ValidityRestrictionType::Time_Start_And_End>();
        return validity && validity->start_validity <= convert_time32(time) &&
            convert_time32(time) <= validity->end_validity;
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
    const Certificate& root = *provider->root_certificate();
    EXPECT_EQ(SignerInfoType::Self, get_type(root.signer_info));
    EXPECT_TRUE(verifies(root, root));
}

TEST_F(NaiveCredentialProviderTest, aa_is_issued_by_root)
{
    std::unique_ptr<NaiveCredentialProvider> provider = issued_provider(*module);
    ASSERT_TRUE(provider);
    EXPECT_TRUE(issued_by(*provider->aa_certificate(), *provider->root_certificate()));
}

TEST_F(NaiveCredentialProviderTest, ticket_is_issued_by_aa_of_credential)
{
    std::unique_ptr<NaiveCredentialProvider> provider = issued_provider(*module);
    ASSERT_TRUE(provider);
    const Credential* credential = provider->signing_credential(aid::CA);
    ASSERT_TRUE(credential);
    EXPECT_EQ(calculate_hash(*crypto, *provider->aa_certificate()), calculate_hash(*crypto, credential->issuer));
    EXPECT_TRUE(issued_by(credential->certificate, credential->issuer));
}

TEST_F(NaiveCredentialProviderTest, credential_key_belongs_to_ticket)
{
    std::unique_ptr<NaiveCredentialProvider> provider = issued_provider(*module);
    ASSERT_TRUE(provider);
    const Credential* credential = provider->signing_credential(aid::CA);
    ASSERT_TRUE(credential);
    const expected<security::PublicKey> key = module->public_key(credential->key);
    ASSERT_TRUE(key.has_value());
    const boost::optional<security::PublicKey> ticket_key = get_verification_key(credential->certificate);
    ASSERT_TRUE(ticket_key);
    EXPECT_EQ(canonical_hexstring(*ticket_key), canonical_hexstring(*key));
}

TEST_F(NaiveCredentialProviderTest, chain_is_valid_at_creation)
{
    std::unique_ptr<NaiveCredentialProvider> provider = issued_provider(*module);
    ASSERT_TRUE(provider);
    const Credential* credential = provider->signing_credential(aid::CA);
    ASSERT_TRUE(credential);
    EXPECT_TRUE(valid_at(credential->certificate, now));
    EXPECT_TRUE(valid_at(*provider->aa_certificate(), now));
    EXPECT_TRUE(valid_at(*provider->root_certificate(), now));
}

TEST_F(NaiveCredentialProviderTest, later_issue_renews_ticket_only)
{
    std::unique_ptr<NaiveCredentialProvider> provider = issued_provider(*module);
    ASSERT_TRUE(provider);
    const Certificate created = provider->signing_credential(aid::CA)->certificate;
    const HashedId8 aa_digest = calculate_hash(*crypto, *provider->aa_certificate());
    const HashedId8 root_digest = calculate_hash(*crypto, *provider->root_certificate());

    const Clock::time_point later = now + std::chrono::hours(22);
    ASSERT_FALSE(provider->issue_certificates(later));
    const Credential* renewed = provider->signing_credential(aid::CA);
    ASSERT_TRUE(renewed);
    EXPECT_TRUE(valid_at(renewed->certificate, later + std::chrono::hours(21)));
    EXPECT_TRUE(issued_by(renewed->certificate, renewed->issuer));
    // renewed ticket is consistent with its issuer, i.e. it ends within its issuer's validity
    EXPECT_TRUE(valid_at(renewed->issuer, later + std::chrono::hours(22)));
    EXPECT_EQ(canonical_hexstring(*get_verification_key(created)),
        canonical_hexstring(*get_verification_key(renewed->certificate)));
    EXPECT_EQ(aa_digest, calculate_hash(*crypto, *provider->aa_certificate()));
    EXPECT_EQ(root_digest, calculate_hash(*crypto, *provider->root_certificate()));
}

TEST_F(NaiveCredentialProviderTest, keys_are_discarded_with_provider)
{
    const std::vector<std::string> software_modules = software_security_module_names();
    if (software_modules.empty()) {
        GTEST_SKIP() << "no software security module built in";
    }

    // a module storing its keys reveals the keys not discarded yet
    struct CountingVisitor : public CredentialVisitor
    {
        void visit(const std::string&) override { ++count; }
        std::size_t count = 0;
    };
    auto storage = std::make_shared<MemoryCredentialStorage>();
    std::unique_ptr<SecurityModule> storing = create_software_security_module(software_modules.front(), storage);
    ASSERT_TRUE(storing);

    std::unique_ptr<NaiveCredentialProvider> provider = issued_provider(*storing);
    ASSERT_TRUE(provider);
    CountingVisitor created;
    ASSERT_FALSE(storage->visit(created));
    EXPECT_EQ(3u, created.count);

    provider.reset();
    CountingVisitor remaining;
    ASSERT_FALSE(storage->visit(remaining));
    EXPECT_EQ(0u, remaining.count);
}
