#ifndef ECC_POINT_HPP_XCESTUEB
#define ECC_POINT_HPP_XCESTUEB

#include <vanetza/common/byte_buffer.hpp>
#include <vanetza/security/ecc_point.hpp>
#include <vanetza/security/v2/serialization.hpp>
#include <cstdint>

namespace vanetza
{
namespace security
{
namespace v2
{

/// forward declaration, see public_key.hpp
enum class PublicKeyAlgorithm: uint8_t;

/// EccPointType specified in TS 103 097 v1.2.1 in section 4.2.6
enum class EccPointType : uint8_t
{
    X_Coordinate_Only = 0,
    Compressed_Lsb_Y_0 = 2,
    Compressed_Lsb_Y_1 = 3,
    Uncompressed = 4
};

/**
 * \brief Determines EccPointType to a given EccPoint
 * \param ecc_point
 * \return type
 */
EccPointType get_type(const EccPoint&);

/**
 * \brief Serializes an EccPoint into a binary archive
 * \param ar to serialize in
 * \param ecc_point to serialize
 * \param pka Public key algorithm used for EccPoint
 */
void serialize(OutputArchive&, const EccPoint&, PublicKeyAlgorithm);

/**
 * \brief Deserializes an EccPoint from a binary archive
 * \param ar with a serialized EccPoint at the beginning,
 * \param ecc_point to deserialize
 * \param pka to get field size of the encoded coordinates
 */
void deserialize(InputArchive&, EccPoint&, PublicKeyAlgorithm);

/**
 * \brief Calculates size of an EccPoint
 * \param ecc_point
 * \return size_t containing the number of octets needed to serialize the EccPoint
 */
size_t get_size(const EccPoint&);

} // namespace v2
} // namespace security
} // namespace vanetza

#endif /* ECC_POINT_HPP_XCESTUEB */
