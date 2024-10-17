#ifndef CAM_FUNCTIONS_HPP_PUFKBEM8
#define CAM_FUNCTIONS_HPP_PUFKBEM8

#include <vanetza/asn1/its/AltitudeConfidence.h>
#include <vanetza/asn1/its/AltitudeValue.h>
#include <vanetza/common/position_fix.hpp>
#include <vanetza/security/cam_ssp.hpp>
#include <vanetza/units/angle.hpp>
#include <vanetza/units/length.hpp>

// forward declaration of asn1c generated struct
struct BasicVehicleContainerLowFrequency;
struct Heading;
struct ReferencePosition;
struct Vanetza_ITS2_BasicVehicleContainerLowFrequency;
struct Vanetza_ITS2_Heading;
struct Vanetza_ITS2_ReferencePosition;

namespace vanetza
{

// forward declaration of CAM message wrappers
namespace asn1 {
    namespace r1 { class Cam; }
    namespace r2 { class Cam; }
}

namespace facilities
{

class PathHistory;

/**
 * Copy PathHistory into BasicVehicleContainerLowFrequency's pathHistory element
 * \param Facilities' path history object (source)
 * \param ASN.1 CAM container (destination)
 */
void copy(const PathHistory&, BasicVehicleContainerLowFrequency&);
void copy(const PathHistory&, Vanetza_ITS2_BasicVehicleContainerLowFrequency&);

/**
 * Check if difference of two given heading values is within a limit
 * \param a one heading
 * \param b another heading
 * \param limit maximum difference (positive)
 * \return true if similar enough
 */
bool similar_heading(const Heading& a, const Heading& b, units::Angle limit);
bool similar_heading(const Heading& a, units::Angle b, units::Angle limit);
bool similar_heading(const Vanetza_ITS2_Heading& a, const Vanetza_ITS2_Heading&b, units::Angle limit);
bool similar_heading(const Vanetza_ITS2_Heading& a, units::Angle b, units::Angle limit);
bool similar_heading(units::Angle a, units::Angle b, units::Angle limit);

/**
 * Calculate distance between positions
 * \param a one position
 * \param b another position
 * \return distance between given positions (or NaN if some position is unavailable)
 */
units::Length distance(const ReferencePosition& a, const ReferencePosition& b);
units::Length distance(const ReferencePosition& a, units::GeoAngle lat, units::GeoAngle lon);
units::Length distance(const Vanetza_ITS2_ReferencePosition& a, const Vanetza_ITS2_ReferencePosition& b);
units::Length distance(const Vanetza_ITS2_ReferencePosition& a, units::GeoAngle lat, units::GeoAngle lon);

/**
 * Check if ASN.1 data element indicates unavailable value
 * \return true if value is available
 */
bool is_available(const Heading&);
bool is_available(const Vanetza_ITS2_Heading&);
bool is_available(const ReferencePosition&);
bool is_available(const Vanetza_ITS2_ReferencePosition&);

/**
 * Copy position information into a ReferencePosition structure from CDD
 */
void copy(const PositionFix&, ReferencePosition&);
void copy(const PositionFix&, Vanetza_ITS2_ReferencePosition&);

/**
 * Convert altitude to AltitudeValue from CDD
 * 
 * It is safe to cast AltitudeValue_t to Vanetza_ITS2_AltitudeValue_t.
 */
AltitudeValue_t to_altitude_value(units::Length);

/**
 * Convert altitude confidence to AltitudeConfidence from CDD
 * 
 * It is safe to cast AltitudeConfidence_t to Vanetza_ITS2_AltitudeConfidence_t.
 */
AltitudeConfidence_t to_altitude_confidence(units::Length);

/**
 * Check if a CAM contains only allowed data elements
 * \param cam CA message
 * \param ssp CA service specific permissions
 * \return true if no forbidden data elements are included
 */
bool check_service_specific_permissions(const asn1::r1::Cam& cam, security::CamPermissions ssp);
bool check_service_specific_permissions(const asn1::r2::Cam& cam, security::CamPermissions ssp);

/**
 * Print CAM content with indentation of nested fields
 * \param os output stream
 * \param cam CA message
 * \param indent indentation marker, by default one tab per level
 * \param start initial level of indentation
 *
 * This function is an idea of Erik de Britto e Silva (erikbritto@github)
 * from University of Antwerp - erik.debrittoesilva@uantwerpen.be
 */
void print_indented(std::ostream& os, const asn1::r1::Cam& cam, const std::string& indent = "\t", unsigned start = 0);
void print_indented(std::ostream& os, const asn1::r2::Cam& cam, const std::string& indent = "\t", unsigned start = 0);

} // namespace facilities
} // namespace vanetza

#endif /* CAM_FUNCTIONS_HPP_PUFKBEM8 */
