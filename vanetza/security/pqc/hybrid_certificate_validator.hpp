#pragma once

#include <vanetza/security/v3/certificate_validator.hpp>
#include <vanetza/security/pqc/fndsa512.hpp>

namespace vanetza
{

class PositionProvider;
class Runtime;

namespace security
{

class Backend;
class CryptoProvider;

namespace v3
{
class CertificateView;
class IssuerLookup;
class LocationChecker;
class RevocationLookup;
class TrustStore;
} // namespace v3

namespace pqc
{

/**
 * Default V3 policy checks plus cryptographic certificate-chain validation.
 *
 * This class is compiled only for the experimental profile. Message
 * signatures remain classical ECC; this validator concerns the nested
 * signatures on certificates in the Root -> AA -> AT chain.
 */
class HybridCertificateValidator : public v3::CertificateValidator
{
public:
    enum class VerificationPolicy
    {
        ClassicalOnly,
        HybridIfPresent,
        HybridRequired,
    };

    /**
     * \param crypto provider calculating certificate hashes and verifying classical signatures
     */
    explicit HybridCertificateValidator(CryptoProvider& crypto);

    Verdict valid_for_signing(const v3::CertificateView&, ItsAid) override;

    void use_runtime(const Runtime*);
    void use_position_provider(PositionProvider*);
    void use_issuer_lookup(const v3::IssuerLookup*);
    void use_location_checker(const v3::LocationChecker*);
    void use_revocation_lookup(const v3::RevocationLookup*);
    void use_trust_store(const v3::TrustStore*);
    void use_pqc_backend(Backend*);
    void use_verification_policy(VerificationPolicy);

    void disable_time_checks(bool);
    void disable_location_checks(bool);
    void disable_chain_consistency_checks(bool);
    void disable_region_consistency_checks(bool);

private:
    bool chain_is_authentic(const v3::CertificateView&) const;
    bool alternative_signature_is_accepted(
        const v3::CertificateView& subject, const v3::CertificateView* issuer) const;

    v3::DefaultCertificateValidator m_policy_validator;
    const v3::IssuerLookup* m_issuer_lookup = nullptr;
    const v3::TrustStore* m_trust_store = nullptr;
    CryptoProvider& m_crypto;
    Backend* m_pqc_backend = nullptr;
    VerificationPolicy m_verification_policy = VerificationPolicy::HybridRequired;
};

} // namespace pqc
} // namespace security
} // namespace vanetza
