#ifndef BACKEND_CRYPTOPP_HPP_JQWA9MLZ
#define BACKEND_CRYPTOPP_HPP_JQWA9MLZ

#include <vanetza/common/byte_buffer.hpp>
#include <vanetza/security/public_key.hpp>
#include <vanetza/security/signature.hpp>
#include <cryptopp/eccrypto.h>
#include <cryptopp/sha.h>

namespace vanetza
{
namespace security
{

// forward declaration
struct Uncompressed;

class BackendCryptoPP
{
public:
    using PrivateKey = CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PrivateKey;
    using PublicKey = CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PublicKey;
    using Signer = CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::Signer;
    using Verifier = CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::Verifier;

    struct KeyPair
    {
        PrivateKey private_key;
        PublicKey public_key;
    };

    /**
     * \brief generate EcdsaSignature, for given data with private_key
     *
     * \param private_key used to sign the data
     * \param data_buffer the data
     * \return EcdsaSignature resulting signature
     */
    EcdsaSignature sign_data(const PrivateKey& private_key, const ByteBuffer& data_buffer);

    /**
     * \brief checks if the data_buffer can be verified with the public_key
     *
     * \param public_key
     * \param data to be verified
     * \param sig signature for verification
     * \return true if the data could be verified
     */
    bool verify_data(const PublicKey& public_key, const ByteBuffer& data, const ByteBuffer& sig);

    /**
     * \brief generate a private key and the corresponding public key
     * \return generated key pair
     */
    KeyPair generate_key_pair();

    /**
     * Create public key from uncrompressed ECC point
     * \param unc uncompressed ECC point (secured message format)
     * \return public key
     */
    PublicKey public_key(const Uncompressed& unc);
};

} // namespace security
} // namespace vanetza

#endif /* BACKEND_CRYPTOPP_HPP_JQWA9MLZ */

