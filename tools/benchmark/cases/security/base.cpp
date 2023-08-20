#include "base.hpp"
#include "vanetza/security/v2/sign_service.hpp"
#include "vanetza/security/straight_verify_service.hpp"
#include <boost/date_time/posix_time/posix_time.hpp>
#include <iostream>

using namespace vanetza;
using namespace vanetza::security;

SecurityBaseCase::SecurityBaseCase() :
    runtime(Clock::at(boost::posix_time::microsec_clock::universal_time())),
    crypto_backend(create_backend("default")),
    certificate_cache(runtime),
    certificate_provider(runtime),
    certificate_validator(*crypto_backend, certificate_cache, trust_store),
    sign_header_policy(runtime, positioning),
    security_entity(create_sign_service(), create_verify_service())
{
    // nothing to do
}

void SecurityBaseCase::prepare()
{
    PositionFix position;
    position.latitude = 49.014420 * units::degree;
    position.longitude = 8.404417 * units::degree;
    position.confidence.semi_major = 25.0 * units::si::meter;
    position.confidence.semi_minor = 25.0 * units::si::meter;
    assert(position.confidence);

    positioning.position_fix(position);
}

std::unique_ptr<SignService> SecurityBaseCase::create_sign_service()
{
    return std::unique_ptr<SignService> {
        new v2::StraightSignService(certificate_provider, *crypto_backend, sign_header_policy)
    };
}

std::unique_ptr<VerifyService> SecurityBaseCase::create_verify_service()
{
    std::unique_ptr<StraightVerifyService> verify_service { new StraightVerifyService(runtime, *crypto_backend, positioning) };
    verify_service->use_certificate_cache(&certificate_cache);
    verify_service->use_certificate_provider(&certificate_provider);
    verify_service->use_certitifcate_validator(&certificate_validator);
    verify_service->use_sign_header_policy(&sign_header_policy);
    return verify_service;
}
