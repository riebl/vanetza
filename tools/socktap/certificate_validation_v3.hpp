#pragma once

#include <memory>
#include <string>

namespace boost
{
namespace program_options
{
class options_description;
class variables_map;
} // namespace program_options
} // namespace boost

namespace vanetza
{

class PositionProvider;
class Runtime;

namespace security
{

class CryptoProvider;

namespace v3
{
class Certificate;
class CertificateValidator;
class LocationChecker;
} // namespace v3
} // namespace security
} // namespace vanetza

/**
 * Owns the profile-specific services selected for a socktap V3 security context.
 *
 * Profile-specific implementations may retain issuer certificates and trust
 * anchors needed by their validator. The strict implementation preserves
 * socktap's established behavior.
 */
class CertificateValidationV3
{
public:
    virtual ~CertificateValidationV3() = default;

    virtual vanetza::security::v3::CertificateValidator& validator() = 0;
    virtual void add_chain_certificate(const vanetza::security::v3::Certificate&) = 0;
};

std::unique_ptr<CertificateValidationV3> create_default_certificate_validation_v3(
    const vanetza::Runtime&, vanetza::security::CryptoProvider&, vanetza::PositionProvider&,
    const vanetza::security::v3::LocationChecker&);

std::unique_ptr<CertificateValidationV3> create_certificate_validation_v3(
    const boost::program_options::variables_map&, const vanetza::Runtime&, vanetza::security::CryptoProvider&,
    vanetza::PositionProvider&, const vanetza::security::v3::LocationChecker&);

void add_certificate_validation_v3_options(boost::program_options::options_description&);
