#ifndef AD03EF9D_246E_48D3_83F0_9983ADF0C454
#define AD03EF9D_246E_48D3_83F0_9983ADF0C454

#include <vanetza/security/sign_service.hpp>
#include <vanetza/security/v2/certificate_provider.hpp>
#include <vanetza/security/v2/secured_message.hpp>
#include <vanetza/security/v2/sign_header_policy.hpp>

namespace vanetza
{
namespace security
{

// forward declarations
class Backend;

namespace v2
{

// forward declarations
class CertificateProvider;

/**
 * SignService immediately signing the message using given
 */
class StraightSignService : public SignService
{
public:
   StraightSignService(CertificateProvider&, Backend&, SignHeaderPolicy&);
   SignConfirm sign(SignRequest&&) override;

private:
    CertificateProvider& m_certificates;
    Backend& m_backend;
    SignHeaderPolicy& m_policy;
};

/**
 * SignService deferring actually signature calculation using EcdsaSignatureFuture
 */
class DeferredSignService : public SignService
{
public:
    DeferredSignService(CertificateProvider&, Backend&, SignHeaderPolicy&);
    SignConfirm sign(SignRequest&&) override;

private:
    CertificateProvider& m_certificates;
    Backend& m_backend;
    SignHeaderPolicy& m_policy;
};

/**
 * SignService without real cryptography but dummy signature
 */
class DummySignService : public SignService
{
public:
    /**
     * \param rt runtime for appropriate generation time
     * \param si signer info attached to header fields of secured message
     */ 
    DummySignService(const Runtime& rt, const SignerInfo& si);
    SignConfirm sign(SignRequest&&) override;

private:
    const Runtime& m_runtime;
    const SignerInfo& m_signer_info;
};

} // namespace v2
} // namespace security
} // namespace vanetza

#endif /* AD03EF9D_246E_48D3_83F0_9983ADF0C454 */
