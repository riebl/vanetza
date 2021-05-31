#ifndef UTILS_HPP_XGC8NRDI
#define UTILS_HPP_XGC8NRDI
#include <vanetza/common/byte_buffer.hpp>
#include <vanetza/asn1/support/OCTET_STRING.h>
#include <vanetza/security/ecc_point.hpp>
#include <vanetza/security/basic_elements.hpp>
#include <vanetza/security/region.hpp>
#include <vanetza/asn1/security/EccP256CurvePoint.h>
#include <vanetza/asn1/security/GeographicRegion.h>
#include <vanetza/asn1/security/TwoDLocation.h>
#include <vanetza/asn1/security/HashedId8.h>
#include <vanetza/asn1/security/HashedId3.h>


namespace vanetza
{
namespace asn1
{
    /**
     * \brief Copies the content from ByteBuffer into OCTET_STRING
     * 
     * \param octet Pointer to the OCTET_STRING
     * \param buffer ByteBuffer containing the info to be copied
     */
    void convert_bytebuffer_to_octet_string(OCTET_STRING_t* octet, const vanetza::ByteBuffer& buffer);
    /**
     * \brief Convertor between Asn1c object to vanetza object (EccPoint)
     * \param curve_point asn1c curve_point
     * \return Vanetza EccPoint
     */
    vanetza::security::EccPoint EccP256CurvePoint_to_EccPoint(const EccP256CurvePoint_t& curve_point);
    /**
     * \brief Convertor between Asn1c object to vanetza object (GeographicRegion)
     * \param curve_point asn1c GeographicRegion
     * \return Vanetza GeographicRegion
     */
    vanetza::security::GeographicRegion GeographicRegionAsn_to_GeographicRegion(const GeographicRegion_t& region);
    /**
     * \brief Convertor between Asn1c object to vanetza object (TwoDLocation)
     * \param curve_point asn1c TwoDLocation
     * \return Vanetza TwoDLocation
     */
    vanetza::security::TwoDLocation TwoDLocationAsn_to_TwoDLocation(const TwoDLocation_t& location);
    /**
     * \brief Convertor between Asn1c object to vanetza object (OCTET_STRING)
     * \param curve_point asn1c OCTET_STRING
     * \return Vanetza ByteBuffer
     */
    vanetza::ByteBuffer OCTET_STRING_to_ByteBuffer(const OCTET_STRING_t& octet);
    /**
     * \brief Convertor between Asn1c object to vanetza object (HashedId8)
     * \param curve_point asn1c HashedId8
     * \return Vanetza HashedId8
     */
    vanetza::security::HashedId8 HashedId8_asn_to_HashedId8(const HashedId8_t& hashed);
    /**
     * \brief Convertor between Asn1c object to vanetza object (HashedId3)
     * \param curve_point asn1c HashedId3
     * \return Vanetza HashedId3
     */
    vanetza::security::HashedId3 HashedId3_asn_to_HashedId3(const HashedId3_t& hashed);
}
}


#endif /* DENM_HPP_XGC8NRDI */
