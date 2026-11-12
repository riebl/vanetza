#include "certificate_validation_v3.hpp"
#include <vanetza/security/backend_crypto_provider.hpp>
#include <vanetza/security/persistence.hpp>
#include <vanetza/security/pqc/fndsa512.hpp>
#include <vanetza/security/pqc/hybrid_certificate_validator.hpp>
#include <vanetza/security/v3/certificate.hpp>
#include <vanetza/security/v3/issuer_memory_lookup.hpp>
#include <vanetza/security/v3/trust_store.hpp>
#include <boost/program_options.hpp>
#include <stdexcept>

namespace po = boost::program_options;

namespace
{

class HybridCertificateValidationV3 : public CertificateValidationV3
{
public:
    HybridCertificateValidationV3(
        const vanetza::Runtime& runtime, vanetza::PositionProvider& positioning,
        const vanetza::security::v3::LocationChecker& location_checker,
        vanetza::security::Backend& ecc_backend) :
        m_pqc_backend(vanetza::security::pqc::create_fndsa512_backend()),
        m_ecc_crypto(ecc_backend),
        m_issuer_lookup(m_ecc_crypto),
        m_trust_store(m_ecc_crypto)
    {
        using Policy =
            vanetza::security::pqc::HybridCertificateValidator::VerificationPolicy;
        m_validator.use_runtime(&runtime);
        m_validator.use_position_provider(&positioning);
        m_validator.use_location_checker(&location_checker);
        m_validator.use_issuer_lookup(&m_issuer_lookup);
        m_validator.use_trust_store(&m_trust_store);
        m_validator.use_backends(&m_ecc_crypto, m_pqc_backend.get());
        m_validator.use_verification_policy(Policy::HybridIfPresent);
    }

    vanetza::security::v3::CertificateValidator& validator() override
    {
        return m_validator;
    }

    vanetza::security::PrivateKey load_authorization_ticket_key(
        const std::string& path) const override
    {
        return vanetza::security::load_private_key_from_der_file(path);
    }

    void add_chain_certificate(const vanetza::security::v3::Certificate& certificate) override
    {
        if (!m_issuer_lookup.insert(certificate)) {
            throw std::invalid_argument(
                "V3 certificate chain contains a certificate that cannot act as an issuer");
        }
        if (certificate.issuer_is_self()) {
            m_trust_store.insert(certificate);
        }
    }

private:
    std::unique_ptr<vanetza::security::pqc::Backend> m_pqc_backend;
    vanetza::security::BackendCryptoProvider m_ecc_crypto;
    vanetza::security::v3::IssuerMemoryLookup m_issuer_lookup;
    vanetza::security::v3::TrustStore m_trust_store;
    vanetza::security::pqc::HybridCertificateValidator m_validator;
};

} // namespace

std::unique_ptr<CertificateValidationV3> create_certificate_validation_v3(
    const po::variables_map& options, const vanetza::Runtime& runtime,
    vanetza::PositionProvider& positioning,
    const vanetza::security::v3::LocationChecker& location_checker,
    vanetza::security::Backend& backend)
{
    if (!options["enable-pqc-verification"].as<bool>()) {
        return create_default_certificate_validation_v3(runtime, positioning, location_checker);
    }
    if (!options.count("certificate") || !options.count("certificate-chain")) {
        throw std::invalid_argument(
            "--enable-pqc-verification requires --certificate, --certificate-key, "
            "and a trusted --certificate-chain");
    }

    return std::make_unique<HybridCertificateValidationV3>(
        runtime, positioning, location_checker, backend);
}

void add_certificate_validation_v3_options(po::options_description& options)
{
    options.add_options()
        ("enable-pqc-verification", po::bool_switch()->default_value(false),
            "Verify hybrid PQC certificate signatures in an external V3 chain.");
}
