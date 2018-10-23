#include "base.hpp"
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
    sign_service(straight_sign_service(certificate_provider, *crypto_backend, sign_header_policy)),
    verify_service(straight_verify_service(runtime, certificate_provider, certificate_validator, *crypto_backend, certificate_cache, sign_header_policy, positioning)),
    security_entity(sign_service, verify_service)
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
