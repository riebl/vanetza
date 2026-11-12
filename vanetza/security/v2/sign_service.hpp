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
class CryptoProvider;
class SecurityModule;

namespace v2
{

// forward declarations
class CertificateProvider;
class CredentialProvider;

/**
 * SignService immediately signing the message using given
 * \deprecated use SecurityModuleSignService, it signs with a private key held by a SecurityModule
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
 * SignService immediately signing the message with the private key of a credential held by a SecurityModule
 */
class SecurityModuleSignService : public SignService
{
public:
    SecurityModuleSignService(SecurityModule&, CryptoProvider&, CredentialProvider&, SignHeaderPolicy&);
    SignConfirm sign(SignRequest&&) override;

private:
    SecurityModule& m_module;
    CryptoProvider& m_crypto;
    CredentialProvider& m_credentials;
    SignHeaderPolicy& m_policy;
};

/**
 * SignService deferring actually signature calculation using EcdsaSignatureFuture
 * \deprecated use SecurityModuleSignService, it signs with a private key held by a SecurityModule
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
    SignerInfo m_signer_info;
};

} // namespace v2
} // namespace security
} // namespace vanetza

#endif /* AD03EF9D_246E_48D3_83F0_9983ADF0C454 */
