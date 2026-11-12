#include "certificate_validation_v3.hpp"
#include <vanetza/common/position_provider.hpp>
#include <vanetza/common/runtime.hpp>
#include <vanetza/security/persistence.hpp>
#include <vanetza/security/v3/certificate_validator.hpp>
#include <vanetza/security/v3/location_checker.hpp>

namespace
{

class DefaultCertificateValidationV3 : public CertificateValidationV3
{
public:
    DefaultCertificateValidationV3(
        const vanetza::Runtime& runtime, vanetza::security::CryptoProvider& crypto,
        vanetza::PositionProvider& positioning, const vanetza::security::v3::LocationChecker& location_checker) :
        m_validator(crypto)
    {
        m_validator.use_runtime(&runtime);
        m_validator.use_position_provider(&positioning);
        m_validator.use_location_checker(&location_checker);
    }

    vanetza::security::v3::CertificateValidator& validator() override
    {
        return m_validator;
    }

    vanetza::security::PrivateKey load_authorization_ticket_key(
        const std::string& path) const override
    {
        return vanetza::security::load_private_key_from_pem_file(path);
    }

    void add_chain_certificate(const vanetza::security::v3::Certificate&) override
    {
    }

private:
    vanetza::security::v3::DefaultCertificateValidator m_validator;
};

} // namespace

std::unique_ptr<CertificateValidationV3> create_default_certificate_validation_v3(
    const vanetza::Runtime& runtime, vanetza::security::CryptoProvider& crypto,
    vanetza::PositionProvider& positioning, const vanetza::security::v3::LocationChecker& location_checker)
{
    return std::make_unique<DefaultCertificateValidationV3>(
        runtime, crypto, positioning, location_checker);
}
