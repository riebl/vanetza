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
 * Default implementation that uses basic logic to check if a position is inside a region.
 * It supports a few region types (e.g., None, Circular, Rectangular) and defaults to false for others.
 */
class DefaultLocationChecker : public LocationChecker
{
    public:
        bool valid_at_location(const asn1::EtsiTs103097Certificate& cert, const PositionFix& location) const override;
};

} // namespace v3
} // namespace security
} // namespace vanetza
