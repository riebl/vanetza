#ifndef PUBLIC_KEY_HPP_DRZFSERF
#define PUBLIC_KEY_HPP_DRZFSERF

#include <vanetza/security/ecc_point.hpp>
#include <vanetza/security/deserialization_error.hpp>
#include <boost/variant.hpp>

namespace vanetza
{
namespace security
{

enum class SymmetricAlgorithm : uint8_t
{
    Aes128_Ccm = 0
};

enum class PublicKeyAlgorithm : uint8_t
{
    Ecdsa_Nistp256_With_Sha256 = 0,
    Ecies_Nistp256 = 1
};

struct ecdsa_nistp256_with_sha256
{
    EccPoint public_key;
};

struct ecies_nistp256
{
    SymmetricAlgorithm supported_symm_alg;
    EccPoint public_key;
};

typedef boost::variant<ecdsa_nistp256_with_sha256, ecies_nistp256> PublicKey;

/**
 * Determines PublcKeyAlgorithm to a given PublicKey
 * \param PublicKey
 * \retunr PublicKeyAlgorithm
 */
PublicKeyAlgorithm get_type(const PublicKey&);

/**
 * Calculates size of a PublicKey
 * \param PublicKey
 * \return size_t containing the number of octets needed to serialize the PublicKey
 */
size_t get_size(const PublicKey&);

/**
 * Deserializes a PublicKey from a binary archive
 * \param archive with a serialized PublicKey at the beginning,
 * \param PublicKey to safe deserialized values in
 * \return size_t of the deserialized publicKey
 */
size_t deserialize(InputArchive&, PublicKey&);

/**
 * Serializes a PublicKey into a binary archive
 * \param achive to serialize in
 * \param PublicKey to serialize
 */
void serialize(OutputArchive&, const PublicKey&);

/**
 * Defines length of uint8_t vectors
 * \param used algorithm
 * \return size_t depending on the used algorithm
 */
std::size_t field_size(PublicKeyAlgorithm);
std::size_t field_size(SymmetricAlgorithm);

} // namespace security
} // namespace vanetza

#endif /* PUBLIC_KEY_HPP_DRZFSERF */
