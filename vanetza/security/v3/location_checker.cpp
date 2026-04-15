#include <vanetza/common/position_fix.hpp>
#include <vanetza/geodesy/country_database.hpp>
#include <vanetza/geodesy/m49_code.hpp>
#include <vanetza/asn1/security/IdentifiedRegion.h>
#include <vanetza/asn1/security/SequenceOfIdentifiedRegion.h>
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
                return check_identified_region(location, region->choice.identifiedRegion);
            default:
                // unknown or future region restriction type — reject conservatively
                return false;
        }
    } else {
        // no region restriction applies
        return true;
    }
}

bool DefaultLocationChecker::check_identified_region(const PositionFix& location, const Vanetza_Security_SequenceOfIdentifiedRegion& seq) const
{
    if (!country_db_ || country_db_->empty())
    {
        // lacking database for country checks
        return permissive_identified_region_;
    }

    // reject any region by default
    bool accepted = false;

    for (int i = 0; i < seq.list.count; ++i) {
        const auto* entry = seq.list.array[i];
        if (!entry) {
            continue;
        }

        if (entry->present == Vanetza_Security_IdentifiedRegion_PR_countryOnly) {
            geodesy::M49Code code(static_cast<uint16_t>(entry->choice.countryOnly));
            geodesy::GeodeticPosition pos(location.latitude, location.longitude);
            if (country_db_->is_inside(code, pos)) {
                return true;
            }
        } else {
            // may accept because of unsupported identified region
            accepted = permissive_identified_region_;
        }
    }

    return accepted;
}

} // namespace v3
} // namespace security
} // namespace vanetza
