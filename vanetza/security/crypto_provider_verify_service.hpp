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

} // namespace v3

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
    CryptoProviderVerifyService(CryptoProvider&, const v3::IssuerLookup* issuers);

    void use_certificate_cache(v3::CertificateCache*);
    void use_certificate_validator(v3::CertificateValidator*);
    void use_sign_header_policy(v3::SignHeaderPolicy*);

    /**
     * Verify secured message
     * \return confirm, its report is Incompatible_Protocol for messages other than v3
     */
    VerifyConfirm verify(const VerifyRequest&) override;
    VerifyConfirm verify(const v3::SecuredMessage&);

private:
    CryptoProvider& m_crypto;
    const v3::IssuerLookup* m_issuers;

    struct {
        v3::CertificateCache* m_cert_cache = nullptr;
        v3::CertificateValidator* m_cert_validator = nullptr;
        v3::SignHeaderPolicy* m_sign_policy = nullptr;
    } m_context_v3;
};

} // namespace security
} // namespace vanetza
