#pragma once
#include <vanetza/security/verify_service.hpp>

namespace vanetza
{
namespace security
{

// forward declarations
class CryptoProvider;

namespace v3
{

// forward declarations
class CertificateCache;
class CertificateValidator;
class IssuerLookup;
class SignHeaderPolicy;
struct SecuredMessage;

/**
 * VerifyService checking signatures of v3 messages by a CryptoProvider
 */
class CryptoProviderVerifyService : public VerifyService
{
public:
    /**
     * \param issuers already checked issuer certificates of authorization tickets,
     *        nullptr accepts tickets without verifying their issuer's signature
     */
    CryptoProviderVerifyService(CryptoProvider&, const IssuerLookup* issuers);

    void use_certificate_cache(CertificateCache*);
    void use_certificate_validator(CertificateValidator*);
    void use_sign_header_policy(SignHeaderPolicy*);

    /**
     * Verify secured message
     * \return confirm, its report is Incompatible_Protocol for messages other than v3
     */
    VerifyConfirm verify(const VerifyRequest&) override;
    VerifyConfirm verify(const SecuredMessage&);

private:
    CryptoProvider& m_crypto;
    const IssuerLookup* m_issuers;
    CertificateCache* m_cert_cache = nullptr;
    CertificateValidator* m_cert_validator = nullptr;
    SignHeaderPolicy* m_sign_policy = nullptr;
};

} // namespace v3
} // namespace security
} // namespace vanetza
