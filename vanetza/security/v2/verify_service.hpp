#ifndef CB901C7B_1A19_45AE_9756_174BAFD6683A
#define CB901C7B_1A19_45AE_9756_174BAFD6683A

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

/**
 * Verify service with basic certificate and signature checks
 */
class StraightVerifyService : public VerifyService
{
public:
    StraightVerifyService(const Runtime&, CertificateProvider&, CertificateValidator&, Backend&,
        CertificateCache&, SignHeaderPolicy&, PositionProvider&);
    VerifyConfirm verify(VerifyRequest&&) override;

private:
    const Runtime& m_runtime;
    CertificateCache& m_cert_cache;
    CertificateProvider& m_cert_provider;
    CertificateValidator& m_cert_validator;
    Backend& m_backend;
    SignHeaderPolicy& m_sign_policy;
    PositionProvider& m_position_provider;
};

} // namespace v2
} // namespace security
} // namespace vanetza

#endif /* CB901C7B_1A19_45AE_9756_174BAFD6683A */
