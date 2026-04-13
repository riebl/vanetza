#include <vanetza/security/v3/asn1_types.hpp>
#include <vanetza/security/v3/distance.hpp>
#include <vanetza/security/v3/geometry.hpp>
#include <vanetza/security/v3/location_checker.hpp>

namespace vanetza
{
namespace security
{
namespace v3
{

bool AllowLocationChecker::valid_at_location(const asn1::EtsiTs103097Certificate&, const PositionFix&) const
{
    return true;
}

bool DenyLocationChecker::valid_at_location(const asn1::EtsiTs103097Certificate&, const PositionFix&) const
{
    return false;
}

bool DefaultLocationChecker::valid_at_location(const asn1::EtsiTs103097Certificate& cert, const PositionFix& location) const
{
    const asn1::GeographicRegion* region = cert.toBeSigned.region;
    if (region) {
        switch (region->present) {
            case Vanetza_Security_GeographicRegion_PR_circularRegion:
                return is_inside(location, region->choice.circularRegion);
            case Vanetza_Security_GeographicRegion_PR_rectangularRegion:
                return is_inside(location, region->choice.rectangularRegion);
            case Vanetza_Security_GeographicRegion_PR_polygonalRegion:
                return is_inside(location, region->choice.polygonalRegion);
            case Vanetza_Security_GeographicRegion_PR_identifiedRegion:
                // IdentifiedRegion carries ISO 3166-1 country codes and/or sub-regional identifiers.
                // Full enforcement requires an external country-boundary dataset (e.g. OpenStreetMap
                // admin-level polygons loaded into a Boost.Geometry R-tree) — see issue #262.
                //
                // When permissive_identified_region_ is true (opt-in), accept without verification.
                // Default: conservative rejection (OutsideRegion) — the ITS station operator must
                // explicitly enable permissive behaviour via set_permissive_identified_region(true).
                return permissive_identified_region_;
            default:
                // unknown or future region restriction type — reject conservatively
                return false;
        }
    } else {
        // no region restriction applies
        return true;
    }
}

} // namespace v3
} // namespace security
} // namespace vanetza
