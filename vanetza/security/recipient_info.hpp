#ifndef RECIPIENT_INFO_HPP_IENLXEUN
#define RECIPIENT_INFO_HPP_IENLXEUN

#include <vanetza/security/basic_elements.hpp>
#include <vanetza/security/public_key.hpp>

namespace vanetza
{
namespace security
{

struct EciesNistP256EncryptedKey
{
    EccPoint v;
    ByteBuffer c;
    std::array<uint8_t, 20> t;
};

typedef boost::variant<EciesNistP256EncryptedKey> Key;

struct RecipientInfo
{
    HashedId8 cert_id;
    Key enc_key;
};

/**
 * Determines PublicKeyAlgorithm to a RecipientInfo
 * \param RecipientInfo
 * \return PublicKeyAlgoritm
 */
PublicKeyAlgorithm get_type(const RecipientInfo&);

/**
 * Calculates size of a RecipientInfo
 * \param RecipientInfo
 * \return size_t containing the number of octets needed to serialize the RecipientInfo
 */
size_t get_size(const RecipientInfo&);

/**
 * Serializes a RecipientInfo into a binary archive
 * \param RecipientInfo to serialize
 * \param achive to serialize in
 */
void serialize(OutputArchive&, const RecipientInfo&);

/**
 * Deserializes a RecipientInfo / RecipientInfo list from a binary archive
 * \param archive with a serialized RecipientInfo / RecipientInfo list at the beginning
 * \param a RecipientInfo / RecipientInfo list to deserialize
 * \return size of the deserialized a RecipientInfo / RecipientInfo list
 */
size_t deserialize(InputArchive&, RecipientInfo&, const SymmetricAlgorithm&);
size_t deserialize(InputArchive&, std::list<RecipientInfo>&, const SymmetricAlgorithm&);

} // namespace security
} // namespace vanetza

#endif /* RECIPIENT_INFO_HPP_IENLXEUN*/
