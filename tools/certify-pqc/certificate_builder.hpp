#pragma once

#include <vanetza/common/clock.hpp>
#include <vanetza/common/its_aid.hpp>
#include <vanetza/security/key_reference.hpp>
#include <vanetza/security/pqc/fndsa512.hpp>
#include <vanetza/security/public_key.hpp>
#include <vanetza/security/v3/certificate.hpp>
#include <string>
#include <vector>

namespace vanetza
{
namespace security
{

class CryptoProvider;
class SecurityModule;

namespace pqc
{
namespace certificate_builder
{

struct CertificateParameters
{
    std::string subject_name;
    int validity_days = 1;
    std::vector<ItsAid> application_ids;
};

v3::Certificate build_ecc_root_certificate(
    CryptoProvider&, SecurityModule&, const KeyReference& subject_key,
    const CertificateParameters&, Clock::time_point now);

v3::Certificate build_hybrid_root_certificate(
    CryptoProvider&, SecurityModule&, Backend&, const KeyReference& subject_key, const SigningKey& subject_pqc_key,
    const CertificateParameters&, Clock::time_point now);

v3::Certificate build_ecc_authorization_authority_certificate(
    CryptoProvider&, SecurityModule&, const KeyReference& issuer_key,
    const v3::Certificate& issuer_certificate,
    const ::vanetza::security::PublicKey& subject_key,
    const CertificateParameters&, Clock::time_point now);

v3::Certificate build_hybrid_authorization_authority_certificate(
    CryptoProvider&, SecurityModule&, Backend&,
    const KeyReference& issuer_key, const KeyReference& issuer_pqc_key,
    const v3::Certificate& issuer_certificate,
    const ::vanetza::security::PublicKey& subject_key, const PublicKey& subject_pqc_key,
    const CertificateParameters&, Clock::time_point now);

v3::Certificate build_ecc_authorization_ticket(
    CryptoProvider&, SecurityModule&, const KeyReference& issuer_key,
    const v3::Certificate& issuer_certificate,
    const ::vanetza::security::PublicKey& subject_key,
    const CertificateParameters&, Clock::time_point now);

v3::Certificate build_hybrid_authorization_ticket(
    CryptoProvider&, SecurityModule&, Backend&,
    const KeyReference& issuer_key, const KeyReference& issuer_pqc_key,
    const v3::Certificate& issuer_certificate,
    const ::vanetza::security::PublicKey& subject_key,
    const CertificateParameters&, Clock::time_point now);

} // namespace certificate_builder
} // namespace pqc
} // namespace security
} // namespace vanetza
