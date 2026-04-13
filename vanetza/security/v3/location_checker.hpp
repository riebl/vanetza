#pragma once
#include <vanetza/asn1/security/Certificate.h>
#include <vanetza/security/v3/asn1_types.hpp>


namespace vanetza
{

// forward declaration
struct PositionFix;

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
 * Supports: no restriction, CircularRegion, RectangularRegion, PolygonalRegion.
 * IdentifiedRegion (ISO 3166 country codes): unsupported; returns false (conservative) unless
 * permissive_identified_region is enabled by the operator (see issue #262).
 * Unknown region types: returns false (conservative).
 */
class DefaultLocationChecker : public LocationChecker
{
    public:
        bool valid_at_location(const asn1::EtsiTs103097Certificate& cert, const PositionFix& location) const override;

        /**
         * When set to true, IdentifiedRegion constraints are accepted without verification
         * until a proper country-boundary dataset is integrated (see issue #262).
         * Default: false — conservative rejection, operator must explicitly opt in.
         */
        void set_permissive_identified_region(bool permissive) {
            permissive_identified_region_ = permissive;
        }

        bool permissive_identified_region() const {
            return permissive_identified_region_;
        }

    private:
        bool permissive_identified_region_ = false;
};

} // namespace v3
} // namespace security
} // namespace vanetza
