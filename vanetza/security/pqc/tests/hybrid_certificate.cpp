#include <vanetza/asn1/security_profile.hpp>
#include VANETZA_ASN1_SECURITY_HEADER(Certificate.h)
#include VANETZA_ASN1_SECURITY_HEADER(PsidGroupPermissions.h)
#include <vanetza/common/its_aid.hpp>
#include <vanetza/security/backend.hpp>
#include <vanetza/security/backend_crypto_provider.hpp>
#include <vanetza/security/pqc/fndsa512.hpp>
#include <vanetza/security/pqc/hybrid_certificate.hpp>
#include <vanetza/security/pqc/hybrid_certificate_validator.hpp>
#include <vanetza/security/v3/asn1_conversions.hpp>
#include <vanetza/security/v3/certificate.hpp>
#include <vanetza/security/v3/issuer_memory_lookup.hpp>
#include <vanetza/security/v3/trust_store.hpp>
#include <gtest/gtest.h>
#include <array>
#include <stdexcept>

using namespace vanetza;
using namespace vanetza::security;
using namespace vanetza::security::v3;

namespace
{

PrivateKey to_private_key(const ecdsa256::PrivateKey& input)
{
    PrivateKey output;
    output.type = KeyType::NistP256;
    output.key.assign(input.key.begin(), input.key.end());
    return output;
}

void set_verification_key(Certificate& certificate, const ecdsa256::PublicKey& key)
{
    auto& indicator = certificate->toBeSigned.verifyKeyIndicator;
    indicator.present = Vanetza_Security_VerificationKeyIndicator_PR_verificationKey;
    auto& verification_key = indicator.choice.verificationKey;
    verification_key.present = Vanetza_Security_PublicVerificationKey_PR_ecdsaNistP256;

    auto& point = verification_key.choice.ecdsaNistP256;
    point.present = Vanetza_Security_EccP256CurvePoint_PR_uncompressedP256;
    OCTET_STRING_fromBuf(
        &point.choice.uncompressedP256.x,
        reinterpret_cast<const char*>(key.x.data()), key.x.size());
    OCTET_STRING_fromBuf(
        &point.choice.uncompressedP256.y,
        reinterpret_cast<const char*>(key.y.data()), key.y.size());
}

void set_issuer(Certificate& certificate, const Certificate* issuer)
{
    if (!issuer) {
        certificate->issuer.present = Vanetza_Security_IssuerIdentifier_PR_self;
        certificate->issuer.choice.self = Vanetza_Security_HashAlgorithm_sha256;
        return;
    }

    const auto digest = issuer->calculate_digest();
    if (!digest) {
        throw std::runtime_error("issuer certificate has no digest");
    }
    certificate->issuer.present = Vanetza_Security_IssuerIdentifier_PR_sha256AndDigest;
    OCTET_STRING_fromBuf(
        &certificate->issuer.choice.sha256AndDigest,
        reinterpret_cast<const char*>(digest->data()), digest->size());
}

void add_all_issue_permissions(Certificate& certificate)
{
    auto* permissions = vanetza::asn1::allocate<v3::asn1::PsidGroupPermissions>();
    permissions->subjectPermissions.present = Vanetza_Security_SubjectPermissions_PR_all;
    permissions->subjectPermissions.choice.all = 0;
    certificate.add_cert_issue_permission(permissions);
}

Certificate make_certificate(
    const ecdsa256::PublicKey& subject_key, const Certificate* issuer, bool authority)
{
    Certificate certificate;
    certificate->version = 3;
    certificate->type = Vanetza_Security_CertificateType_explicit;
    set_issuer(certificate, issuer);

    if (authority) {
        static const char name[] = "Hybrid test CA";
        certificate->toBeSigned.id.present = Vanetza_Security_CertificateId_PR_name;
        OCTET_STRING_fromBuf(
            &certificate->toBeSigned.id.choice.name, name, sizeof(name) - 1);
        add_all_issue_permissions(certificate);
    } else {
        certificate->toBeSigned.id.present = Vanetza_Security_CertificateId_PR_none;
        certificate.add_app_permission(aid::CA, ByteBuffer { 1, 0, 0 });
    }

    static const std::array<char, 3> craca_id {{ 0, 0, 0 }};
    OCTET_STRING_fromBuf(
        &certificate->toBeSigned.cracaId, craca_id.data(), craca_id.size());
    certificate->toBeSigned.crlSeries = 0;
    certificate->toBeSigned.validityPeriod.start = 0;
    certificate->toBeSigned.validityPeriod.duration.present =
        Vanetza_Security_Duration_PR_years;
    certificate->toBeSigned.validityPeriod.duration.choice.years = 10;
    set_verification_key(certificate, subject_key);
    return certificate;
}

void sign_hybrid(
    Certificate& subject, const Certificate* issuer,
    Backend& ecc_backend, pqc::Backend& pqc_backend,
    const PrivateKey& ecc_key, const pqc::PrivateKey& pqc_key)
{
    pqc::sign_alternative_certificate(
        subject, issuer, ecc_backend, pqc_backend, pqc_key);
    pqc::sign_primary_certificate(subject, issuer, ecc_backend, ecc_key);
}

void set_unsupported_alternative_signature(Certificate& certificate)
{
    pqc::clear_alternative_signature(certificate);
    auto* signature = vanetza::asn1::allocate<v3::asn1::Signature>();
    signature->present = Vanetza_Security_Signature_PR_ecdsaNistP256Signature;
    auto& r = signature->choice.ecdsaNistP256Signature.rSig;
    r.present = Vanetza_Security_EccP256CurvePoint_PR_x_only;
    const std::array<char, 32> zeroes {{}};
    OCTET_STRING_fromBuf(&r.choice.x_only, zeroes.data(), zeroes.size());
    OCTET_STRING_fromBuf(
        &signature->choice.ecdsaNistP256Signature.sSig,
        zeroes.data(), zeroes.size());
    certificate->toBeSigned.altSignatureValue = signature;
}

struct Chain
{
    explicit Chain(bool hybrid_material = true) :
        ecc_backend(create_backend_or_throw("default")),
        ecc_crypto(*ecc_backend),
        pqc_backend(pqc::create_fndsa512_backend()),
        root_ecc_pair(ecc_backend->generate_key_pair()),
        aa_ecc_pair(ecc_backend->generate_key_pair()),
        at_ecc_pair(ecc_backend->generate_key_pair()),
        root_ecc_key(to_private_key(root_ecc_pair.private_key)),
        aa_ecc_key(to_private_key(aa_ecc_pair.private_key)),
        root_pqc_pair(pqc_backend->generate_key_pair()),
        aa_pqc_pair(pqc_backend->generate_key_pair())
    {
        root = make_certificate(root_ecc_pair.public_key, nullptr, true);
        if (hybrid_material) {
            pqc::set_alternative_public_key(root, root_pqc_pair.public_key);
            sign_hybrid(root, nullptr, *ecc_backend, *pqc_backend, root_ecc_key, root_pqc_pair.private_key);
        } else {
            pqc::sign_primary_certificate(root, nullptr, *ecc_backend, root_ecc_key);
        }

        aa = make_certificate(aa_ecc_pair.public_key, &root, true);
        if (hybrid_material) {
            pqc::set_alternative_public_key(aa, aa_pqc_pair.public_key);
            sign_hybrid(aa, &root, *ecc_backend, *pqc_backend, root_ecc_key, root_pqc_pair.private_key);
        } else {
            pqc::sign_primary_certificate(aa, &root, *ecc_backend, root_ecc_key);
        }

        at = make_certificate(at_ecc_pair.public_key, &aa, false);
        if (hybrid_material) {
            sign_hybrid(at, &aa, *ecc_backend, *pqc_backend, aa_ecc_key, aa_pqc_pair.private_key);
        } else {
            pqc::sign_primary_certificate(at, &aa, *ecc_backend, aa_ecc_key);
        }
    }

    std::unique_ptr<Backend> ecc_backend;
    BackendCryptoProvider ecc_crypto;
    std::unique_ptr<pqc::Backend> pqc_backend;
    ecdsa256::KeyPair root_ecc_pair;
    ecdsa256::KeyPair aa_ecc_pair;
    ecdsa256::KeyPair at_ecc_pair;
    PrivateKey root_ecc_key;
    PrivateKey aa_ecc_key;
    pqc::KeyPair root_pqc_pair;
    pqc::KeyPair aa_pqc_pair;
    Certificate root;
    Certificate aa;
    Certificate at;
};

v3::CertificateValidator::Verdict validate(
    Chain& chain, pqc::HybridCertificateValidator::VerificationPolicy policy)
{
    TrustStore trust_store { chain.ecc_crypto };
    trust_store.insert(chain.root);

    IssuerMemoryLookup issuer_lookup { chain.ecc_crypto };
    if (!issuer_lookup.insert(chain.root) || !issuer_lookup.insert(chain.aa)) {
        throw std::runtime_error("cannot populate issuer lookup");
    }

    pqc::HybridCertificateValidator validator { chain.ecc_crypto };
    validator.use_issuer_lookup(&issuer_lookup);
    validator.use_trust_store(&trust_store);
    validator.use_pqc_backend(chain.pqc_backend.get());
    validator.use_verification_policy(policy);
    validator.disable_time_checks(true);
    validator.disable_location_checks(true);
    return validator.valid_for_signing(chain.at, aid::CA);
}

} // namespace

TEST(HybridCertificate, fndsa512_backend_rejects_invalid_material_sizes)
{
    auto backend = pqc::create_fndsa512_backend();
    const auto key_pair = backend->generate_key_pair();
    const ByteBuffer message { 1, 2, 3, 4 };
    const auto signature = backend->sign(key_pair.private_key, message);

    EXPECT_EQ(pqc::fndsa512_public_key_size, key_pair.public_key.bytes.size());
    EXPECT_EQ(pqc::fndsa512_private_key_size, key_pair.private_key.bytes.size());
    EXPECT_EQ(pqc::fndsa512_signature_size, signature.bytes.size());
    EXPECT_TRUE(backend->verify(key_pair.public_key, message, signature));

    pqc::PublicKey short_key { ByteBuffer(1, 0) };
    pqc::PrivateKey short_private_key { ByteBuffer(1, 0) };
    pqc::Signature short_signature { ByteBuffer(1, 0) };
    EXPECT_THROW(backend->sign(short_private_key, message), std::invalid_argument);
    EXPECT_FALSE(backend->verify(short_key, message, signature));
    EXPECT_FALSE(backend->verify(key_pair.public_key, message, short_signature));
}

TEST(HybridCertificate, material_roundtrips_through_oer)
{
    Chain chain;
    Certificate decoded;
    ASSERT_TRUE(decoded.decode(chain.at.encode()));

    EXPECT_EQ(pqc::MaterialState::EndEntity, pqc::alternative_material_state(decoded));
    EXPECT_FALSE(pqc::get_alternative_public_key(decoded));
    const auto signature = pqc::get_alternative_signature(decoded);
    ASSERT_TRUE(signature);
    EXPECT_EQ(pqc::fndsa512_signature_size, signature->bytes.size());

    Certificate decoded_aa;
    ASSERT_TRUE(decoded_aa.decode(chain.aa.encode()));
    EXPECT_EQ(pqc::MaterialState::Authority, pqc::alternative_material_state(decoded_aa));
    ASSERT_TRUE(pqc::get_alternative_public_key(decoded_aa));
    ASSERT_TRUE(pqc::get_alternative_signature(decoded_aa));
}

TEST(HybridCertificate, verifies_both_nested_signature_layers)
{
    Chain chain;
    EXPECT_TRUE(pqc::verify_alternative_certificate(
        chain.root, nullptr, chain.ecc_crypto, *chain.pqc_backend));
    EXPECT_TRUE(pqc::verify_primary_certificate(chain.root, nullptr, chain.ecc_crypto));
    EXPECT_TRUE(pqc::verify_alternative_certificate(
        chain.aa, &chain.root, chain.ecc_crypto, *chain.pqc_backend));
    EXPECT_TRUE(pqc::verify_primary_certificate(chain.aa, &chain.root, chain.ecc_crypto));
    EXPECT_TRUE(pqc::verify_alternative_certificate(
        chain.at, &chain.aa, chain.ecc_crypto, *chain.pqc_backend));
    EXPECT_TRUE(pqc::verify_primary_certificate(chain.at, &chain.aa, chain.ecc_crypto));
}

TEST(HybridCertificate, certificate_hash_rejects_a_non_matching_issuer)
{
    Chain chain;

    EXPECT_THROW(
        pqc::calculate_certificate_hash(
            chain.ecc_crypto, HashAlgorithm::SHA256, chain.at, &chain.root,
            pqc::SignatureLayer::Primary),
        std::invalid_argument);
    EXPECT_FALSE(pqc::verify_primary_certificate(
        chain.at, &chain.root, chain.ecc_crypto));
    EXPECT_FALSE(pqc::verify_alternative_certificate(
        chain.at, &chain.root, chain.ecc_crypto, *chain.pqc_backend));
}

TEST(HybridCertificate, signing_rejects_mismatched_alternative_private_key)
{
    Chain chain;
    const auto unrelated_key_pair = chain.pqc_backend->generate_key_pair();
    pqc::clear_alternative_signature(chain.at);

    EXPECT_THROW(
        pqc::sign_alternative_certificate(
            chain.at, &chain.aa, *chain.ecc_backend, *chain.pqc_backend,
            unrelated_key_pair.private_key),
        std::invalid_argument);
    EXPECT_FALSE(pqc::get_alternative_signature(chain.at));
}

TEST(HybridCertificate, signing_rejects_mismatched_primary_private_key)
{
    Chain chain;
    const auto unrelated_key_pair = chain.ecc_backend->generate_key_pair();

    EXPECT_THROW(
        pqc::sign_primary_certificate(
            chain.at, &chain.aa, *chain.ecc_backend,
            to_private_key(unrelated_key_pair.private_key)),
        std::invalid_argument);
    EXPECT_TRUE(pqc::verify_primary_certificate(
        chain.at, &chain.aa, chain.ecc_crypto));
}

TEST(HybridCertificate, primary_signature_covers_alternative_signature)
{
    Chain chain;
    auto signature = pqc::get_alternative_signature(chain.at);
    ASSERT_TRUE(signature);
    signature->bytes.front() ^= 0x01;
    pqc::set_alternative_signature(chain.at, *signature);

    EXPECT_FALSE(pqc::verify_alternative_certificate(
        chain.at, &chain.aa, chain.ecc_crypto, *chain.pqc_backend));
    EXPECT_FALSE(pqc::verify_primary_certificate(chain.at, &chain.aa, chain.ecc_crypto));

    pqc::sign_primary_certificate(
        chain.at, &chain.aa, *chain.ecc_backend, chain.aa_ecc_key);
    EXPECT_TRUE(pqc::verify_primary_certificate(chain.at, &chain.aa, chain.ecc_crypto));
    EXPECT_FALSE(pqc::verify_alternative_certificate(
        chain.at, &chain.aa, chain.ecc_crypto, *chain.pqc_backend));
}

TEST(HybridCertificate, validator_accepts_authentic_hybrid_chain)
{
    Chain chain;
    EXPECT_EQ(CertificateValidator::Verdict::Valid,
        validate(chain, pqc::HybridCertificateValidator::VerificationPolicy::HybridRequired));
}

TEST(HybridCertificate, validator_verifies_authority_certificates_in_the_chain)
{
    Chain chain;
    ASSERT_TRUE(chain.aa->signature);
    ASSERT_EQ(Vanetza_Security_Signature_PR_ecdsaNistP256Signature,
        chain.aa->signature->present);

    auto& encoded_s = chain.aa->signature->choice.ecdsaNistP256Signature.sSig;
    ASSERT_TRUE(encoded_s.buf);
    ASSERT_GT(encoded_s.size, 0u);
    encoded_s.buf[0] ^= 0x01;

    // Reissue the AT for the modified AA so leaf verification still succeeds.
    chain.at = make_certificate(chain.at_ecc_pair.public_key, &chain.aa, false);
    sign_hybrid(
        chain.at, &chain.aa, *chain.ecc_backend, *chain.pqc_backend,
        chain.aa_ecc_key, chain.aa_pqc_pair.private_key);

    EXPECT_TRUE(pqc::verify_primary_certificate(
        chain.at, &chain.aa, chain.ecc_crypto));
    EXPECT_FALSE(pqc::verify_primary_certificate(
        chain.aa, &chain.root, chain.ecc_crypto));
    EXPECT_EQ(CertificateValidator::Verdict::Untrusted,
        validate(chain, pqc::HybridCertificateValidator::VerificationPolicy::HybridRequired));
}

TEST(HybridCertificate, validator_policy_is_explicit_for_classical_chains)
{
    Chain chain(false);
    EXPECT_EQ(CertificateValidator::Verdict::Untrusted,
        validate(chain, pqc::HybridCertificateValidator::VerificationPolicy::HybridRequired));
    EXPECT_EQ(CertificateValidator::Verdict::Valid,
        validate(chain, pqc::HybridCertificateValidator::VerificationPolicy::HybridIfPresent));
    EXPECT_EQ(CertificateValidator::Verdict::Valid,
        validate(chain, pqc::HybridCertificateValidator::VerificationPolicy::ClassicalOnly));
}

TEST(HybridCertificate, hybrid_policy_rejects_incomplete_authority_material)
{
    Chain chain;
    pqc::clear_alternative_signature(chain.aa);
    pqc::sign_primary_certificate(
        chain.aa, &chain.root, *chain.ecc_backend, chain.root_ecc_key);

    chain.at = make_certificate(chain.at_ecc_pair.public_key, &chain.aa, false);
    sign_hybrid(
        chain.at, &chain.aa, *chain.ecc_backend, *chain.pqc_backend,
        chain.aa_ecc_key, chain.aa_pqc_pair.private_key);

    EXPECT_EQ(pqc::MaterialState::Inconsistent,
        pqc::alternative_material_state(chain.aa));
    EXPECT_EQ(CertificateValidator::Verdict::Untrusted,
        validate(chain, pqc::HybridCertificateValidator::VerificationPolicy::HybridIfPresent));
    EXPECT_EQ(CertificateValidator::Verdict::Valid,
        validate(chain, pqc::HybridCertificateValidator::VerificationPolicy::ClassicalOnly));
}

TEST(HybridCertificate, classical_policy_still_verifies_outer_signature)
{
    Chain chain;
    auto signature = pqc::get_alternative_signature(chain.at);
    ASSERT_TRUE(signature);
    signature->bytes.front() ^= 0x01;
    pqc::set_alternative_signature(chain.at, *signature);
    pqc::sign_primary_certificate(
        chain.at, &chain.aa, *chain.ecc_backend, chain.aa_ecc_key);

    EXPECT_EQ(CertificateValidator::Verdict::Untrusted,
        validate(chain, pqc::HybridCertificateValidator::VerificationPolicy::HybridRequired));
    EXPECT_EQ(CertificateValidator::Verdict::Untrusted,
        validate(chain, pqc::HybridCertificateValidator::VerificationPolicy::HybridIfPresent));
    EXPECT_EQ(CertificateValidator::Verdict::Valid,
        validate(chain, pqc::HybridCertificateValidator::VerificationPolicy::ClassicalOnly));
}

TEST(HybridCertificate, every_policy_rejects_a_broken_primary_signature)
{
    Chain chain;
    ASSERT_TRUE(chain.at->signature);
    ASSERT_EQ(Vanetza_Security_Signature_PR_ecdsaNistP256Signature,
        chain.at->signature->present);

    auto& encoded_s = chain.at->signature->choice.ecdsaNistP256Signature.sSig;
    ASSERT_TRUE(encoded_s.buf);
    ASSERT_GT(encoded_s.size, 0u);
    encoded_s.buf[0] ^= 0x01;

    EXPECT_EQ(CertificateValidator::Verdict::Untrusted,
        validate(chain, pqc::HybridCertificateValidator::VerificationPolicy::HybridRequired));
    EXPECT_EQ(CertificateValidator::Verdict::Untrusted,
        validate(chain, pqc::HybridCertificateValidator::VerificationPolicy::HybridIfPresent));
    EXPECT_EQ(CertificateValidator::Verdict::Untrusted,
        validate(chain, pqc::HybridCertificateValidator::VerificationPolicy::ClassicalOnly));
}

TEST(HybridCertificate, authorization_ticket_rejects_alternative_public_key)
{
    Chain chain;
    pqc::set_alternative_public_key(chain.at, chain.aa_pqc_pair.public_key);
    EXPECT_EQ(pqc::MaterialState::Inconsistent,
        pqc::alternative_material_state(chain.at));
}

TEST(HybridCertificate, unsupported_alternative_choice_is_not_treated_as_absent)
{
    Chain chain;
    set_unsupported_alternative_signature(chain.at);
    pqc::sign_primary_certificate(
        chain.at, &chain.aa, *chain.ecc_backend, chain.aa_ecc_key);

    EXPECT_EQ(pqc::MaterialState::Inconsistent,
        pqc::alternative_material_state(chain.at));
    EXPECT_EQ(CertificateValidator::Verdict::Untrusted,
        validate(chain, pqc::HybridCertificateValidator::VerificationPolicy::HybridIfPresent));
}
