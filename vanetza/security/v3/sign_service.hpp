#pragma once
#include <vanetza/security/sign_service.hpp>
#include <vanetza/security/v3/certificate_provider.hpp>
#include <vanetza/security/v3/certificate_validator.hpp>
#include <vanetza/security/v3/sign_header_policy.hpp>

namespace vanetza
{
namespace security
{

// forward declarations
class Backend;

namespace v3
{

/**
 * SignService immediately signing the message using given
 */
class StraightSignService : public SignService
{
public:
   StraightSignService(CertificateProvider&, Backend&, SignHeaderPolicy&, CertificateValidator&);
   SignConfirm sign(SignRequest&&) override;

private:
    CertificateProvider & m_certificates;
    Backend& m_backend;
    SignHeaderPolicy& m_policy;
    CertificateValidator& m_validator;
};
    

/**
 * SignService without real cryptography but dummy signature
 */
class DummySignService : public SignService
{
public:
    /**
     * \param rt runtime for appropriate generation time
     */ 
    DummySignService(const Runtime& rt);
    SignConfirm sign(SignRequest&&) override;

private:
    const Runtime& m_runtime;
};

} // namespace v3
} // namespace security
} // namespace vanetza
