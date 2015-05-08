#ifndef SECURED_MESSAGE_HPP_MO3HBSXG
#define SECURED_MESSAGE_HPP_MO3HBSXG


#include <cstdint>
#include <boost/serialization/vector.hpp>
#include <vanetza/security/header_field.hpp>
#include <vanetza/security/trailer_field.hpp>
#include <vanetza/security/payload.hpp>


namespace vanetza
{
namespace security
{

enum class Profile : uint8_t
{
    Generic = 0,
    CAM = 1,
    DENM = 2
};

struct SecuredMessage
{
    uint8_t protocol_version;
    Profile security_profile;
    std::list<HeaderField> header_fields;
    std::list<TrailerField> trailer_fields;
    std::list<Payload> payload;
};

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
void deserialize(InputArchive& ar, SecuredMessage& message);

} // namespace security
} // namespace vanetza

#endif /* SECURED_MESSAGE_HPP_MO3HBSXG */

