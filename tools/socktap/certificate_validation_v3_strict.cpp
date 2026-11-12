#include "certificate_validation_v3.hpp"

std::unique_ptr<CertificateValidationV3> create_certificate_validation_v3(
    const boost::program_options::variables_map&, const vanetza::Runtime& runtime,
    vanetza::security::CryptoProvider& crypto, vanetza::PositionProvider& positioning,
    const vanetza::security::v3::LocationChecker& location_checker)
{
    return create_default_certificate_validation_v3(runtime, crypto, positioning, location_checker);
}

void add_certificate_validation_v3_options(boost::program_options::options_description&)
{
}
