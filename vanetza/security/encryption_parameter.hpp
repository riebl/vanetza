#ifndef ENCRYPTION_PARAMETER_HPP_EIAWNAWY
#define ENCRYPTION_PARAMETER_HPP_EIAWNAWY

#include <vanetza/security/serialization.hpp>
#include <boost/variant.hpp>

namespace vanetza
{
namespace security
{

enum class SymmetricAlgorithm : uint8_t;

using Nonce = std::array<uint8_t, 12>;

typedef boost::variant<Nonce> EncryptionParameter;

/**
 * Determines SymmetricAlgorithm to a given PublicKey
 * \param EncryptionParameter
 * \return SymmetricAlgorithm
 */
SymmetricAlgorithm get_type(const EncryptionParameter&);

/**
 * Serializes an EncryptionParameter into a binary archive
 * \param achive to serialize in
 * \param EncryptionParameter to serialize
 */
void serialize(OutputArchive&, const EncryptionParameter&);

/**
 * Calculates size of an EncryptionParameter
 * \param EncryptionParameter
 * \return size_t containing the number of octets needed to serialize the EncryptionParameter
 */
size_t get_size(const EncryptionParameter&);

/**
 * Deserializes an EncryptionParameter from a binary archive
 * \param archive with a serialized EncryptionParameter at the beginning
 * \param EncryptionParameter to safe deserialized values in
 * \return size of deserialized EncryptionParameter
 */
size_t deserialize(InputArchive&, EncryptionParameter&, SymmetricAlgorithm& sym);

} // namespace security
} // namespace vanetzta

#endif /* ENCRYPTION_PARAMETER_HPP_EIAWNAWY */
