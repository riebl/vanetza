#ifndef TRAILER_FIELDS_HPP_3PDKGWCQ
#define TRAILER_FIELDS_HPP_3PDKGWCQ

#include <vanetza/common/byte_buffer.hpp>
#include <vanetza/security/signature.hpp>
#include <boost/variant/variant.hpp>
#include <cstdint>

namespace vanetza
{
namespace security
{

enum class TrailerFieldType : uint8_t
{
        Signature = 1
};

typedef boost::variant<Signature> TrailerField;

/**
 * Determines TrailerFieldType to a given TrailerField
 * \param TrailerField
 * \return TrailerFieldType
 */
TrailerFieldType get_type(const TrailerField&);

/**
 * Calculates size of a TrailerField
 * \param TrailerField
 * \return size_t containing the number of octets needed to serialize the TrailerField
 */
size_t get_size(const TrailerField&);

/**
 * Serializes a TrailerField into a binary archive
 * \param TrailerField to serialize
 * \param achive to serialize in
 */
void serialize(OutputArchive&, const TrailerField&);

/**
 * Deserializes a TrailerField from a binary archive
 * \param archive with a serialized TrailerField at the beginning
 * \param TrailerField to deserialize
 * \return size of the deserialized TrailerField
 */
size_t deserialize(InputArchive&, TrailerField&);

/**
* Serialize TrailerField and return the ByteBuffer representation,
* use Signature.ECC_POINT.x, Signatur.s
* \param trailer_field field to be converted
* \return ByteBuffer
*/
ByteBuffer extract_signature_buffer(const TrailerField& trailer_field);

} // namespace security
} // namespace vanetza

#endif /* TRAILER_FIELDS_HPP_3PDKGWCQ */
