#pragma once
#include <vanetza/asn1/security/Certificate.h>
#include <vanetza/security/v3/asn1_types.hpp>

// forward declaration
struct Vanetza_Security_SequenceOfIdentifiedRegion;

namespace vanetza
{

// forward declarations
struct PositionFix;
namespace geodesy { class CountryDatabase; }

namespace security
{
namespace v3
{

/**
 * LocationChecker Interface
 * Abstract base class defining the interface for location validation.
 */
class LocationChecker
{
public:
    // Returns true if the given PositionFix lies within the specified GeographicRegion.
    virtual bool valid_at_location(const asn1::EtsiTs103097Certificate& cert, const PositionFix& location) const = 0;
    virtual ~LocationChecker() = default;
};

/**
 * Always allow all the requests
 */
class AllowLocationChecker : public LocationChecker
{
public:
    bool valid_at_location(const asn1::EtsiTs103097Certificate& cert, const PositionFix& location) const override;
};

/**
 * Always deny all the requests
 */
class DenyLocationChecker : public LocationChecker
{
public:
    bool valid_at_location(const asn1::EtsiTs103097Certificate& cert, const PositionFix& location) const override;
};

/**
 * Default implementation that checks whether a position lies within a certificate's GeographicRegion.
 * Supports: no restriction, CircularRegion, RectangularRegion, PolygonalRegion, IdentifiedRegion
 * (only ISO 3166/M49 country codes).
 * For unsupported IdentifiedRegion variants, the permissive flag controls their acceptance or rejection.
 * IdentifiedRegion (ISO 3166 country codes): unsupported; returns false (conservative) unless
 * Entirely unknown region types are always rejected conservatively.
 */
class DefaultLocationChecker : public LocationChecker
{
public:
    bool valid_at_location(const asn1::EtsiTs103097Certificate& cert, const PositionFix& location) const override;

    /**
     * Change permissive behaviour regarding unsupported IdentifiedRegion types.
     *
     * When set to true, unsupported IdentifiedRegion (country and region, country and sub-regions)
     * are not checked but still accepted. These regions are only defined for the United States, i.e.
     * they have no meaning for European C-ITS deployments.
     * Default behaviour is conservative rejection (false), user must explicitly opt in.
     */
    void set_permissive_identified_region(bool permissive)
    {
        permissive_identified_region_ = permissive;
    }

    bool permissive_identified_region() const
    {
        return permissive_identified_region_;
    }

    /**
     * Register country database for IdentifiedRegion validations.
     *
     * If a database is registered, validation of countryOnly IdentifiedRegion takes place.
     * If database is missing, validation falls back to the defined permissive behaviour.
     */
    void use_country_database(const geodesy::CountryDatabase* db)
    {
        country_db_ = db;
    }

private:
    bool check_identified_region(const PositionFix& location, const Vanetza_Security_SequenceOfIdentifiedRegion& seq) const;

    bool permissive_identified_region_ = false;
    const geodesy::CountryDatabase* country_db_ = nullptr;
};

} // namespace v3
} // namespace security
} // namespace vanetza
