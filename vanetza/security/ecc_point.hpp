#ifndef ECC_POINT_HPP_XCESTUEB
#define ECC_POINT_HPP_XCESTUEB

#include <vanetza/common/byte_buffer.hpp>
#include <vanetza/security/serialization.hpp>
#include <boost/variant.hpp>
#include <array>
#include <cstdint>

namespace vanetza
{
namespace security
{

enum class PublicKeyAlgorithm: uint8_t;
enum class EccPointType : uint8_t
{
    X_Coordinate_Only = 0,
    Compressed_Lsb_Y_0 = 2,
    Compressed_Lsb_Y_1 = 3,
    Uncompressed = 4
};

struct X_Coordinate_Only
{
    ByteBuffer x;
};

struct Compressed_Lsb_Y_0
{
    ByteBuffer x;
};

struct Compressed_Lsb_Y_1
{
    ByteBuffer x;
};

struct Uncompressed
{
    ByteBuffer x;
    ByteBuffer y;
};

typedef boost::variant<X_Coordinate_Only, Compressed_Lsb_Y_0, Compressed_Lsb_Y_1, Uncompressed> EccPoint;

/**
 * Determines EccPointType to a given EccPoint
 * \param EccPoint
 * \Return EccPointType
 */
EccPointType get_type(const EccPoint&);

/**
 * Serializes an EccPoint into a binary archive
 * \param achive to serialize in
 * \param EccPoint to serialize
 */
void serialize(OutputArchive&, const EccPoint&);

/**
 * Deserializes an EccPoint from a binary archive
 * \param archive with a serialized EccPoint at the beginning,
 * \param EccPoint to deserialize
 * \param PublicKeyAlgorithm to get field size of the encoded coordinates
 */
void deserialize(InputArchive&, EccPoint&, PublicKeyAlgorithm);

/**
 * Calculates size of an EccPoint
 * \param EccPoint
 * \return size_t containing the number of octets needed to serialize the EccPoint
 */
size_t get_size(const EccPoint&);

} //namespace security
} //namespace vanetza

#endif /* ECC_POINT_HPP_XCESTUEB */
