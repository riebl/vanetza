#ifndef SIGNER_INFO_HPP_9K6GXK4R
#define SIGNER_INFO_HPP_9K6GXK4R

#include <vanetza/security/certificate.hpp>
#include <vanetza/security/length_coding.hpp>
#include <vanetza/security/signer_info_fwd.hpp>
#include <boost/variant.hpp>
#include <list>

namespace vanetza
{
namespace security
{

/**
 * Determines SignerInfoType to a SignerInfo field
 * \param SignerInfo
 * \return SignerInfoType
 */
SignerInfoType get_type(const SignerInfo&);

/**
 * Calculates size of an object
 * \param Object
 * \return size_t containing the number of octets needed to serialize the object
 */
size_t get_size(const CertificateDigestWithOtherAlgorithm&);
size_t get_size(const SignerInfo&);

/**
 * Serializes an object into a binary archive
 * \param achive to serialize in
 * \param object to serialize
 */
void serialize(OutputArchive&, const CertificateDigestWithOtherAlgorithm&);
void serialize(OutputArchive&, const SignerInfo&);

/**
 * Deserializes an object from a binary archive
 * \param archive with a serialized object at the beginning
 * \param object to deserialize
 * \return size of the deserialized object
 */
size_t deserialize(InputArchive&, CertificateDigestWithOtherAlgorithm&);
size_t deserialize(InputArchive&, SignerInfo&);

} // namespace security
} // namespace vanetza

#endif /* SIGNER_INFO_HPP_9K6GXK4R */

