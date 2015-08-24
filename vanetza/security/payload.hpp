#ifndef PAYLOAD_HPP_R8IXQBSL
#define PAYLOAD_HPP_R8IXQBSL

#include <cstdint>
#include <boost/variant.hpp>
#include <vanetza/common/byte_buffer.hpp>
#include <vanetza/security/serialization.hpp>

namespace vanetza
{
namespace security
{

enum class PayloadType : uint8_t
{
    Unsecured = 0,
    Signed = 1,
    Encrypted = 2,
    Signed_External = 3,
    Signed_And_Encrypted = 4
};

struct Payload
{
    PayloadType type;
    ByteBuffer buffer;
};

/**
 * Determines PayloadType to a given Payload
 * \param Payload
 * \return PayloadType
 */
PayloadType get_type(const Payload&);

/**
 * Calculates size of Payload
 * \param Payload
 * \return size_t containing the number of octets needed to serialize the Payload
 */
size_t get_size(const Payload&);

/**
 * Serializes an object into a binary archive
 * \param object to serialize
 * \param achive to serialize in,
 */
void serialize(OutputArchive& ar, const ByteBuffer&);
void serialize(OutputArchive& ar, const Payload&);

/**
 * Deserializes an object from a binary archive
 * \param archive with a serialized object at the beginning
 * \param object to deserialize
 * \return size of the deserialized object
 */
size_t deserialize(InputArchive& ar, ByteBuffer&);
size_t deserialize(InputArchive& ar, Payload&);

} // namespace security
} // namespace vanetza

#endif /* PAYLOAD_HPP_R8IXQBSL */

