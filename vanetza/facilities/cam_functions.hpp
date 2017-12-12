#ifndef CAM_FUNCTIONS_HPP_PUFKBEM8
#define CAM_FUNCTIONS_HPP_PUFKBEM8

#include <vanetza/asn1/its/Heading.h>
#include <vanetza/asn1/its/ReferencePosition.h>
#include <vanetza/security/cam_ssp.hpp>
#include <vanetza/units/angle.hpp>
#include <vanetza/units/length.hpp>

// forward declaration of asn1c generated struct
struct BasicVehicleContainerLowFrequency;

namespace vanetza
{

// forward declaration of CAM message wrapper
namespace asn1 { class Cam; }

namespace facilities
{

class PathHistory;

/**
 * Copy PathHistory into BasicVehicleContainerLowFrequency's pathHistory element
 * \param Facilities' path history object (source)
 * \param ASN.1 CAM container (destination)
 */
void copy(const PathHistory&, BasicVehicleContainerLowFrequency&);

/**
 * Check if difference of two given heading values is within a limit
 * \param a one heading
 * \param b another heading
 * \param limit maximum difference (positive)
 * \return true if similar enough
 */
bool similar_heading(const Heading& a, const Heading& b, units::Angle limit);
bool similar_heading(const Heading& a, units::Angle b, units::Angle limit);
bool similar_heading(units::Angle a, units::Angle b, units::Angle limit);

/**
 * Calculate distance between positions
 * \param a one position
 * \param b another position
 * \return distance between given positions (or NaN if some position is unavailable)
 */
units::Length distance(const ReferencePosition_t& a, const ReferencePosition_t& b);
units::Length distance(const ReferencePosition_t& a, units::GeoAngle lat, units::GeoAngle lon);

/**
 * Check if ASN.1 data element indicates unavailable value
 * \return true if value is available
 */
bool is_available(const Heading&);
bool is_available(const ReferencePosition_t&);

/**
 * Check if a CAM contains only allowed data elements
 * \param cam CA message
 * \param ssp CA service specific permissions
 * \return true if no forbidden data elements are included
 */
bool check_service_specific_permissions(const asn1::Cam& cam, security::CamPermissions ssp);

} // namespace facilities
} // namespace vanetza

#endif /* CAM_FUNCTIONS_HPP_PUFKBEM8 */
