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
class CryptoProvider;
class SecurityModule;

namespace v3
{

// forward declarations
class CredentialProvider;

/**
 * SignService immediately signing the message using given
 * \deprecated use SecurityModuleSignService, it signs with a private key held by a SecurityModule
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
 * SignService immediately signing the message with the private key of a credential held by a SecurityModule
 */
class SecurityModuleSignService : public SignService
{
public:
    SecurityModuleSignService(
        SecurityModule&, CryptoProvider&, CredentialProvider&, SignHeaderPolicy&, CertificateValidator&);
    SignConfirm sign(SignRequest&&) override;

private:
    CredentialProvider& m_credentials;
    SecurityModule& m_module;
    CryptoProvider& m_crypto;
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
    explicit DummySignService(const Runtime& rt);
    SignConfirm sign(SignRequest&&) override;

private:
    const Runtime& m_runtime;
};

} // namespace v3
} // namespace security
} // namespace vanetza
