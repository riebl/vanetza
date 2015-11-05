#ifndef SECURED_MESSAGE_HPP_MO3HBSXG
#define SECURED_MESSAGE_HPP_MO3HBSXG

#include <cstdint>
#include <list>
#include <vanetza/security/header_field.hpp>
#include <vanetza/security/trailer_field.hpp>
#include <vanetza/security/payload.hpp>


namespace vanetza
{
namespace security
{

struct SecuredMessageV2
{
    std::list<HeaderField> header_fields;
    std::list<TrailerField> trailer_fields;
    Payload payload;

    unsigned protocol_version() const { return 2; }
};

using SecuredMessage = SecuredMessageV2;

/**
 * Calculates size of a SecuredMessage object
 * \param SecuredMessage to calculate size
 * \return size_t containing the number of octets needed to serialize the object
 */
size_t get_size(const SecuredMessage&);

/**
 * Serializes a SecuredMessage into a binary archive
 * \param SecuredMessage to serialize
 * \param achive to serialize in
 */
void serialize(OutputArchive& ar, const SecuredMessage& message);

/**
 * Deserializes a SecuredMessage from a binary archive
 * \param archive with a serialized SecuredMessage at the beginning,
 * \param SecuredMessage to safe deserialized values in
 * \return size of deserialized SecuredMessage
 */
size_t deserialize(InputArchive& ar, SecuredMessage& message);

} // namespace security
} // namespace vanetza

#endif /* SECURED_MESSAGE_HPP_MO3HBSXG */

