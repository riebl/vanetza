#include <vanetza/security/backend.hpp>
#include <vanetza/security/backend_crypto_provider.hpp>
#include <vanetza/security/crypto_provider_verify_service.hpp>
#include <vanetza/security/straight_verify_service.hpp>

namespace vanetza
{
namespace security
{

StraightVerifyService::StraightVerifyService(const Runtime& runtime, Backend& backend, PositionProvider& position) :
    m_runtime(runtime), m_backend(backend), m_position_provider(position)
{
}

void StraightVerifyService::use_certificate_cache(v2::CertificateCache* cache)
{
    m_context_v2.m_cert_cache = cache;
}

void StraightVerifyService::use_certificate_provider(v2::CertificateProvider* provider)
{
    m_context_v2.m_cert_provider = provider;
}

void StraightVerifyService::use_certificate_validator(v2::CertificateValidator* validator)
{
    m_context_v2.m_cert_validator = validator;
}

void StraightVerifyService::use_sign_header_policy(v2::SignHeaderPolicy* policy)
{
    m_context_v2.m_sign_policy = policy;
}

void StraightVerifyService::use_certificate_cache(v3::CertificateCache* cache)
{
    m_context_v3.m_cert_cache = cache;
}

void StraightVerifyService::use_certificate_validator(v3::CertificateValidator* validator)
{
    m_context_v3.m_cert_validator = validator;
}

void StraightVerifyService::use_sign_header_policy(v3::SignHeaderPolicy* policy)
{
    m_context_v3.m_sign_policy = policy;
}

void StraightVerifyService::use_issuer_lookup(const v3::IssuerLookup* issuers)
{
    m_context_v3.m_issuer_lookup = issuers;
}

CryptoProviderVerifyService StraightVerifyService::delegate(CryptoProvider& crypto) const
{
    CryptoProviderVerifyService service { m_runtime, crypto, m_position_provider };
    service.use_certificate_cache(m_context_v2.m_cert_cache);
    service.use_certificate_validator(m_context_v2.m_cert_validator);
    service.use_sign_header_policy(m_context_v2.m_sign_policy);
    service.use_certificate_cache(m_context_v3.m_cert_cache);
    service.use_certificate_validator(m_context_v3.m_cert_validator);
    service.use_sign_header_policy(m_context_v3.m_sign_policy);
    service.use_issuer_lookup(m_context_v3.m_issuer_lookup);
    return service;
}

VerifyConfirm StraightVerifyService::verify(const VerifyRequest& request)
{
    BackendCryptoProvider crypto { m_backend };
    return delegate(crypto).verify(request);
}

VerifyConfirm StraightVerifyService::verify(const v2::SecuredMessage& msg)
{
    BackendCryptoProvider crypto { m_backend };
    return delegate(crypto).verify(msg);
}

VerifyConfirm StraightVerifyService::verify(const v3::SecuredMessage& msg)
{
    BackendCryptoProvider crypto { m_backend };
    return delegate(crypto).verify(msg);
}

} // namespace security
} // namespace vanetza
