#ifndef HEADER_FIELDS_HPP_IHIAKD4K
#define HEADER_FIELDS_HPP_IHIAKD4K

#include <vanetza/security/basic_elements.hpp>
#include <vanetza/security/encryption_parameter.hpp>
#include <vanetza/security/recipient_info.hpp>
#include <vanetza/security/region.hpp>
#include <vanetza/security/signer_info.hpp>

namespace vanetza
{
namespace security
{

enum class HeaderFieldType : uint8_t
{
    Generation_Time = 0,                    // Time64
    Generation_Time_Confidence = 1,         // Time64WithStandardDeviation
    Expiration = 2,                         // Time32
    Generation_Location = 3,                // TreeDLocation
    Request_Unrecognized_Certificate = 4,   // std::list<HashedId3>
    Message_Type = 5,                       // uint16 -> uint16be_t
    Signer_Info = 128,                      // SignerInfo
    Recipient_Info = 129,                   // std::list<RecipientInfo>
    Encryption_Parameters = 130             // EncryptionParameters
};

typedef boost::variant<std::list<HashedId3>, Time32, Time64, uint16_t, SignerInfo,
    Time64WithStandardDeviation, ThreeDLocation, std::list<RecipientInfo>, EncryptionParameter> HeaderField;

/**
 * Determines HeaderFieldType to a given HeaderField
 * \param HeaderField
 * \return HeaderFieldType
 */
HeaderFieldType get_type(const HeaderField& field);

/**
 * Calculates size of an object
 * \param Object
 * \return size_t containing the number of octets needed to serialize the object
 */
size_t get_size(const HeaderField& field);

/**
 * Serializes an object into a binary archive
 * \param object to serialize
 * \param achive to serialize in,
 */
void serialize(OutputArchive& ar, const HeaderField& field);

/**
 * Deserializes an object from a binary archive
 * \param archive with a serialized object at the beginning
 * \param object to deserialize
 * \return size of the deserialized object
 */
size_t deserialize(InputArchive& ar, std::list<HeaderField>& list);
size_t deserialize(InputArchive& ar, HeaderField&);

} // namespace security
} // namespace vanetza

#endif /* HEADER_FIELDS_HPP_IHIAKD4K */

