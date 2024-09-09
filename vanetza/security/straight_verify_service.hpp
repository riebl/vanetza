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
    void use_certificate_provider(v2::CertificateProvider*);
    void use_certitifcate_validator(v2::CertificateValidator*);
    void use_sign_header_policy(v2::SignHeaderPolicy*);

    void use_certificate_cache(v3::CertificateCache*);
    void use_sign_header_policy(v3::SignHeaderPolicy*);

    VerifyConfirm verify(const VerifyRequest&) override;
    VerifyConfirm verify(const v2::SecuredMessage&);
    VerifyConfirm verify(const v3::SecuredMessage&);

private:
    const Runtime& m_runtime;
    Backend& m_backend;
    PositionProvider& m_position_provider;

    struct {
        v2::CertificateCache* m_cert_cache = nullptr;
        v2::CertificateProvider* m_cert_provider = nullptr;
        v2::CertificateValidator* m_cert_validator = nullptr;
        v2::SignHeaderPolicy* m_sign_policy = nullptr;

        constexpr bool complete() const
        {
            return m_cert_cache && m_cert_provider && m_cert_validator && m_sign_policy;
        }
    } m_context_v2;

    struct {
        v3::CertificateCache* m_cert_cache = nullptr;
        v3::SignHeaderPolicy* m_sign_policy = nullptr;
    } m_context_v3;
};

} // namespace security
} // namespace vanetza
