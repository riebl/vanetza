#ifndef TRAILER_FIELD_HPP_3PDKGWCQ
#define TRAILER_FIELD_HPP_3PDKGWCQ

#include <vanetza/common/byte_buffer.hpp>
#include <vanetza/security/v2/signature.hpp>
#include <boost/variant/variant.hpp>
#include <cstdint>

namespace vanetza
{
namespace security
{
namespace v2
{

/// TrailerFieldType specified in TS 103 097 v1.2.1, section 5.7
enum class TrailerFieldType : uint8_t
{
    Signature = 1
};

/// TrailerField specified in TS 103 097 v1.2.1, section 5.6
using TrailerField = boost::variant<Signature>;

/**
 * \brief Determines TrailerFieldType to a given TrailerField
 * \param field
 * \return type
 */
TrailerFieldType get_type(const TrailerField&);

/**
 * \brief Calculates size of a TrailerField
 * \param field
 * \return number of octets needed to serialize the TrailerField
 */
size_t get_size(const TrailerField&);

/**
 * \brief Serializes a TrailerField into a binary archive
 * \param ar to serialize in
 * \param field to serialize
 */
void serialize(OutputArchive&, const TrailerField&);

/**
 * \brief Deserializes a TrailerField from a binary archive
 * \param ar with a serialized TrailerField at the beginning
 * \param field to deserialize
 * \return size of the deserialized TrailerField
 */
size_t deserialize(InputArchive&, TrailerField&);

/**
 * \brief resolve type for matching TrailerFieldType
 *
 * This is kind of the reverse function of get_type(const TrailerField&)
 */
template<TrailerFieldType>
struct trailer_field_type;

template<>
struct trailer_field_type<TrailerFieldType::Signature> { using type = Signature; };

} // namespace v2
} // namespace security
} // namespace vanetza

#endif /* TRAILER_FIELD_HPP_3PDKGWCQ */
