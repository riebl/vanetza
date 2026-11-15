#include <vanetza/geodesy/geodesy.hpp>
#include <vanetza/security/crypto_provider.hpp>
#include <vanetza/security/security_module.hpp>

int main()
{
    using namespace vanetza;

    // reference code depending on private dependencies, i.e. GeographicLib and the crypto libraries
    geodesy::distance(geodesy::GeodeticPosition {}, geodesy::GeodeticPosition {});
    security::create_crypto_provider();
    security::create_security_module();
    return 0;
}
