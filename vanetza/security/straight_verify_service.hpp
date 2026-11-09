#pragma once
#include <vanetza/security/verify_service.hpp>

namespace vanetza
{

// forward declaration
class PositionProvider;
class Runtime;

namespace security
{

// forward declarations
class Backend;
class CryptoProvider;
class CryptoProviderVerifyService;

namespace v2
{

// forward declarations
class CertificateCache;
class CertificateProvider;
class CertificateValidator;
class SignHeaderPolicy;

} // namespace v2

namespace v3
{

// forward declarations
class CertificateCache;
class CertificateValidator;
class IssuerLookup;
class SignHeaderPolicy;

} // namespace v3

/**
 * Verify service with basic certificate and signature checks
 */
class StraightVerifyService : public VerifyService
{
public:
    StraightVerifyService(const Runtime&, Backend&, PositionProvider&);

    void use_certificate_cache(v2::CertificateCache*);
    /**
     * \deprecated unused, requests for own certificates are reported to the v2 sign header policy
     */
    void use_certificate_provider(v2::CertificateProvider*);
    void use_certificate_validator(v2::CertificateValidator*);
    void use_sign_header_policy(v2::SignHeaderPolicy*);

    void use_certificate_cache(v3::CertificateCache*);
    void use_certificate_validator(v3::CertificateValidator*);
    void use_sign_header_policy(v3::SignHeaderPolicy*);
    void use_issuer_lookup(const v3::IssuerLookup* issuers);

    VerifyConfirm verify(const VerifyRequest&) override;
    VerifyConfirm verify(const v2::SecuredMessage&);
    VerifyConfirm verify(const v3::SecuredMessage&);

private:
    // verify service configured with the given components
    CryptoProviderVerifyService delegate(CryptoProvider&) const;

    const Runtime& m_runtime;
    Backend& m_backend;
    PositionProvider& m_position_provider;

    struct {
        v2::CertificateCache* m_cert_cache = nullptr;
        v2::CertificateProvider* m_cert_provider = nullptr;
        v2::CertificateValidator* m_cert_validator = nullptr;
        v2::SignHeaderPolicy* m_sign_policy = nullptr;
    } m_context_v2;

    struct {
        v3::CertificateCache* m_cert_cache = nullptr;
        v3::CertificateValidator* m_cert_validator = nullptr;
        v3::SignHeaderPolicy* m_sign_policy = nullptr;
        const v3::IssuerLookup* m_issuer_lookup = nullptr;
    } m_context_v3;
};

} // namespace security
} // namespace vanetza
