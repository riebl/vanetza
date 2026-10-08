#include <vanetza/geodesy/geodesy.hpp>
#include <vanetza/security/backend.hpp>

int main()
{
    using namespace vanetza;

    // reference code depending on private dependencies, i.e. GeographicLib and the crypto backend
    geodesy::distance(geodesy::GeodeticPosition {}, geodesy::GeodeticPosition {});
    return security::create_backend("default") ? 0 : 1;
}
