#pragma once
#include <vanetza/common/its_aid.hpp>
#include <vanetza/security/v3/location_checker.hpp>

namespace vanetza
{

// forward declarations
class PositionProvider;
class Runtime;

namespace security
{
namespace v3
{

// forward declarations
class Certificate;
class CertificateView;
class IssuerLookup;
class RevocationLookup;
class TrustStore;

class CertificateValidator
{
public:
    enum class Verdict
    {
        Unknown,
        Valid,
        Expired,
        Revoked,
        Untrusted,
        OutsideRegion,
        InsufficientPermission,
        Misconfiguration,
    };

    /**
     * Check if a certificate can be used for signing a message
     * \param certificate pre-validated AT certificate
     * \param app ITS-AID of the message to be signed
     */
    virtual Verdict valid_for_signing(const CertificateView& certificate, ItsAid app) = 0;

    virtual ~CertificateValidator() = default;
};

class DefaultCertificateValidator : public CertificateValidator
{
public:
    Verdict valid_for_signing(const CertificateView&, ItsAid) override;
    
    void use_runtime(const Runtime* runtime);
    void use_position_provider(PositionProvider* provider);
    void use_issuer_lookup(const IssuerLookup* lookup);
    void use_location_checker(const LocationChecker* checker);
    void use_revocation_lookup(const RevocationLookup* lookup);
    void use_trust_store(const TrustStore* store);

    void disable_time_checks(bool flag);
    void disable_location_checks(bool flag);

private:
    const Certificate* find_issuer_certificate(const CertificateView& certificate) const;
    bool chain_is_consistent(const CertificateView& signing_cert, ItsAid its_aid) const;
    bool chain_is_revoked(const CertificateView& signing_cert) const;
    bool check_consistency(const CertificateView& subject, const CertificateView& issuer, ItsAid its_aid) const;
    bool is_chain_anchored(const CertificateView& signing_cert) const;

    const Runtime* m_runtime = nullptr;
    PositionProvider* m_position_provider = nullptr;
    const IssuerLookup* m_issuer_lookup = nullptr;
    const LocationChecker* m_location_checker = nullptr;
    const RevocationLookup* m_revocation_lookup = nullptr;
    const TrustStore* m_trust_store = nullptr;
    bool m_disable_time_checks = false;
    bool m_disable_location_checks = false;
};

class NullCertificateValidator : public CertificateValidator
{
public:
    Verdict valid_for_signing(const CertificateView&, ItsAid) override
    {
        return Verdict::Valid;
    }
};

} // namespace v3
} // namespace security
} // namespace vanetza
