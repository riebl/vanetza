#ifndef BACKEND_HPP_ZMRDTY2O
#define BACKEND_HPP_ZMRDTY2O

#include <vanetza/common/byte_buffer.hpp>
#include <vanetza/common/factory.hpp>
#include <vanetza/security/ecdsa256.hpp>
#include <vanetza/security/ecdsa_signature.hpp>
#include <vanetza/security/hash_algorithm.hpp>
#include <vanetza/security/private_key.hpp>
#include <vanetza/security/public_key.hpp>
#include <vanetza/security/signature.hpp>
#include <boost/optional/optional.hpp>
#include <memory>
#include <string>

namespace vanetza
{
namespace security
{

/**
 * Interface to cryptographic features
 */
class Backend
{
public:
    /**
     * \brief calculate signature for given data and private key
     *
     * \param private_key Secret private key
     * \param data buffer with plaintext data
     * \return calculated signature
     */
    virtual EcdsaSignature sign_data(const ecdsa256::PrivateKey& private_key, const ByteBuffer& data) = 0;

    /**
     * \brief calculate signature for given digest and private key
     * 
     * \param private_key secret private key
     * \param digest hash value of data
     * \return calculated signature
     */
    virtual Signature sign_digest(const PrivateKey&, const ByteBuffer& digest) = 0;

    /**
     * \brief try to verify data using public key and signature
     *
     * \param public_key Public key
     * \param data plaintext
     * \param sig signature of data
     * \return true if the data could be verified
     */
    virtual bool verify_data(const ecdsa256::PublicKey& public_key, const ByteBuffer& data, const EcdsaSignature& sig) = 0;

    /**
     * \brief try to verify digest using public key and signature
     * 
     * \param public_key public key
     * \param digest hash value of data
     * \param sig signature of data
     * \return true if data could be verified
     */
    virtual bool verify_digest(const PublicKey& public_key, const ByteBuffer& digest, const Signature& sig) = 0;

    /**
     * \brief decompress a possibly compressed elliptic curve point
     *
     * \param ecc_point elliptic curve point
     * \return uncompressed point
     */
    virtual boost::optional<Uncompressed> decompress_point(const EccPoint& ecc_point) = 0;

    /**
     * \brief calculate hash value of data
     * 
     * \param algo hash algorithm
     * \param data buffer with data
     * \return buffer containing calculated hash value
     */
    virtual ByteBuffer calculate_hash(HashAlgorithm algo, const ByteBuffer& data) = 0;

    virtual ~Backend() = default;
};

/**
 * \brief get factory containing builtin backend implementations
 *
 * Included set of backends depends on CMake build configuration.
 * At least the "Null" backend is always included.
 * \return factory
 */
const Factory<Backend>& builtin_backends();

/**
 * \brief create a backend instance
 *
 * A backend named "default" is guaranteed not to return a nullptr.
 * However, it might be a dummy backend.
 *
 * \param name identifying name of backend implementation
 * \param factory build backend registered by name from this factory
 * \return backend instance (if available) or nullptr
 */
std::unique_ptr<Backend> create_backend(const std::string& name, const Factory<Backend>& = builtin_backends());

} // namespace security
} // namespace vanetza

#endif /* BACKEND_HPP_ZMRDTY2O */

