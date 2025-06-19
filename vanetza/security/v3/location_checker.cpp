#include <vanetza/security/v3/asn1_types.hpp>
#include <vanetza/security/v3/distance.hpp>
#include <vanetza/security/v3/location_checker.hpp>


namespace vanetza
{
namespace security
{
namespace v3
{

bool AllowLocationChecker::valid_at_location(const asn1::EtsiTs103097Certificate& cert, const PositionFix& location) const
{
    return true;
}

bool DenyLocationChecker::valid_at_location(const asn1::EtsiTs103097Certificate& cert, const PositionFix& location) const
{
    return false;
}

bool DefaultLocationChecker::valid_at_location(const asn1::EtsiTs103097Certificate& cert, const PositionFix& location)
{
    const asn1::GeographicRegion* region = cert.toBeSigned.region;
    if (region) {
        switch (region->present) {
            case Vanetza_Security_GeographicRegion_PR_circularRegion:
                return is_inside(location, region->choice.circularRegion);
            case Vanetza_Security_GeographicRegion_PR_rectangularRegion:
                return is_inside(location, region->choice.rectangularRegion);
            case Vanetza_Security_GeographicRegion_PR_polygonalRegion:
                // not supported yet
                return false;
            case Vanetza_Security_GeographicRegion_PR_identifiedRegion:
                // not supported yet
                return false;
            default:
                // unknown region restriction
                return false;
        }
    } else {
        // no region restriction applies
        return true;
    }
    return true;
}

} // namespace v3
} // namespace security
} // namespace vanetza
