#pragma once
#include <vanetza/security/verify_service.hpp>

namespace vanetza
{

// forward declarations
class PositionProvider;
class Runtime;

namespace security
{

// forward declarations
class CryptoProvider;

namespace v2
{

// forward declarations
class CertificateCache;
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
 * VerifyService checking signatures of v2 and v3 messages by a CryptoProvider
 */
class CryptoProviderVerifyService : public VerifyService
{
public:
    CryptoProviderVerifyService(const Runtime&, CryptoProvider&, PositionProvider&);

    void use_certificate_cache(v2::CertificateCache*);
    void use_certificate_validator(v2::CertificateValidator*);
    void use_sign_header_policy(v2::SignHeaderPolicy*);

    void use_certificate_cache(v3::CertificateCache*);
    void use_certificate_validator(v3::CertificateValidator*);
    void use_sign_header_policy(v3::SignHeaderPolicy*);

    /**
     * \param issuers already checked issuer certificates of v3 authorization tickets,
     *        nullptr (default) accepts v3 tickets without verifying their issuer's signature
     */
    void use_issuer_lookup(const v3::IssuerLookup* issuers);

    VerifyConfirm verify(const VerifyRequest&) override;
    VerifyConfirm verify(const v2::SecuredMessage&);
    VerifyConfirm verify(const v3::SecuredMessage&);

private:
    const Runtime& m_runtime;
    CryptoProvider& m_crypto;
    PositionProvider& m_position_provider;

    struct {
        v2::CertificateCache* m_cert_cache = nullptr;
        v2::CertificateValidator* m_cert_validator = nullptr;
        v2::SignHeaderPolicy* m_sign_policy = nullptr;

        constexpr bool complete() const
        {
            return m_cert_cache && m_cert_validator && m_sign_policy;
        }
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
