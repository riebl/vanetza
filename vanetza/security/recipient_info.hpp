#ifndef RECIPIENT_INFO_HPP_IENLXEUN
#define RECIPIENT_INFO_HPP_IENLXEUN

#include <vanetza/security/basic_elements.hpp>
#include <vanetza/security/public_key.hpp>

namespace vanetza
{
namespace security
{

/**
 * According to TS 103 097 V1.2.1, section 5.9
 */
struct EciesNistP256EncryptedKey
{
    EccPoint v;
    ByteBuffer c;
    std::array<uint8_t, 16> t;
};

typedef boost::variant<EciesNistP256EncryptedKey, ByteBuffer> Key;

/**
 * According to TS 103 097 V1.2.1, section 5.8
 */
struct RecipientInfo
{
    HashedId8 cert_id;
    Key enc_key;

    PublicKeyAlgorithm pk_encryption() const;
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
 * \param achive Destination of serialized object
 * \param info RecipientInfo to serialize
 * \param sym Applicable symmetric algorithm
 */
void serialize(OutputArchive&, const RecipientInfo&, SymmetricAlgorithm);

/**
 * Deserialize a RecipientInfo
 * \param archive Input starting with serialized RecipientInfo
 * \param info Deserialized RecipientInfo
 * \param sym Symmetric algorithm required to deserialize encrypted key
 * \return length of deserialized RecipientInfo in bytes
 */
size_t deserialize(InputArchive&, RecipientInfo&, const SymmetricAlgorithm&);

} // namespace security
} // namespace vanetza

#endif /* RECIPIENT_INFO_HPP_IENLXEUN*/
