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

/**
 * Verify service with basic certificate and signature checks
 */
class StraightVerifyService : public VerifyService
{
public:
    StraightVerifyService(const Runtime&, v2::CertificateProvider&, v2::CertificateValidator&, Backend&,
        v2::CertificateCache&, v2::SignHeaderPolicy&, PositionProvider&);
    VerifyConfirm verify(VerifyRequest&&) override;
    VerifyConfirm verify(const v2::SecuredMessage&);
    VerifyConfirm verify(const v3::SecuredMessage&);

private:
    const Runtime& m_runtime;
    v2::CertificateCache& m_cert_cache;
    v2::CertificateProvider& m_cert_provider;
    v2::CertificateValidator& m_cert_validator;
    Backend& m_backend;
    v2::SignHeaderPolicy& m_sign_policy;
    PositionProvider& m_position_provider;
};

} // namespace security
} // namespace vanetza
