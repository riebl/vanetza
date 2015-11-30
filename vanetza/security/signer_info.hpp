#ifndef SIGNER_INFO_HPP_9K6GXK4R
#define SIGNER_INFO_HPP_9K6GXK4R

#include <vanetza/security/basic_elements.hpp>
#include <vanetza/security/public_key.hpp>
#include <boost/variant/variant.hpp>
#include <cstdint>
#include <list>

namespace vanetza
{
namespace security
{

struct Certificate;

enum class SignerInfoType : uint8_t
{
    Self = 0,                                   // nothing -> nullptr_t
    Certificate_Digest_With_SHA256 = 1,         // HashedId8
    Certificate = 2,                            // Certificate
    Certificate_Chain = 3,                      // std::list<Certificate>
    Certificate_Digest_With_Other_Algorithm = 4 // CertificateDigestWithOtherAlgorithm
};

struct CertificateDigestWithOtherAlgorithm
{
    PublicKeyAlgorithm algorithm;
    HashedId8 digest;
};

using SignerInfo = boost::variant<
    std::nullptr_t,
    HashedId8,
    boost::recursive_wrapper<Certificate>,
    std::list<Certificate>,
    CertificateDigestWithOtherAlgorithm
>;

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
