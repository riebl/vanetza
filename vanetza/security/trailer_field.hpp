#ifndef TRAILER_FIELDS_HPP_3PDKGWCQ
#define TRAILER_FIELDS_HPP_3PDKGWCQ

#include <vanetza/security/signature.hpp>
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
 * Assignes TrailerFieldType to a given TrailerField
 * \param TrailerField
 * \return TrailerFieldType
 */
TrailerFieldType get_type(const TrailerField&);

/**
 * Calculates size of an object
 * \param Object
 * \return size_t containing the number of octets needed to serialize the object
 */
size_t get_size(const TrailerField&);
size_t get_size(const std::list<TrailerField>&);

/**
 * Serializes an object into a binary archive
 * \param object to serialize
 * \param achive to serialize in,
 */
void serialize(OutputArchive&, const std::list<TrailerField>&);
void serialize(OutputArchive&, const TrailerField&);

/**
 * Deserializes an object from a binary archive
 * \param archive with a serialized object at the beginning
 * \param object to deserialize
 * \return size of the deserialized object
 */
size_t deserialize(InputArchive&, std::list<TrailerField>&);
size_t deserialize(InputArchive&, TrailerField&);

} // namespace security
} // namespace vanetza

#endif /* TRAILER_FIELDS_HPP_3PDKGWCQ */

