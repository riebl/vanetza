#ifndef CAM_FUNCTIONS_HPP_PUFKBEM8
#define CAM_FUNCTIONS_HPP_PUFKBEM8

#include <vanetza/asn1/gen/Heading.h>
#include <vanetza/units/angle.hpp>

// forward declaration of asn1c generated struct
struct BasicVehicleContainerLowFrequency;

namespace vanetza
{
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

} // namespace facilities
} // namespace vanetza

#endif /* CAM_FUNCTIONS_HPP_PUFKBEM8 */
