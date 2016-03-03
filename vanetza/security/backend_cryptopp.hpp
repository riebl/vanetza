#ifndef BACKEND_CRYPTOPP_HPP_JQWA9MLZ
#define BACKEND_CRYPTOPP_HPP_JQWA9MLZ

#include <vanetza/common/byte_buffer.hpp>
#include <vanetza/security/ecdsa256.hpp>
#include <vanetza/security/signature.hpp>
#include <cryptopp/eccrypto.h>
#include <cryptopp/osrng.h>
#include <cryptopp/sha.h>

namespace vanetza
{
namespace security
{

class BackendCryptoPP
{
public:
    using PrivateKey = CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PrivateKey;
    using PublicKey = CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PublicKey;
    using Signer = CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::Signer;
    using Verifier = CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::Verifier;

    /**
     * \brief generate EcdsaSignature, for given data with private_key
     *
     * \param private_key used to sign the data
     * \param data_buffer the data
     * \return EcdsaSignature resulting signature
     */
    EcdsaSignature sign_data(const ecdsa256::PrivateKey& private_key, const ByteBuffer& data_buffer);

    /**
     * \brief checks if the data_buffer can be verified with the public_key
     *
     * \param public_key
     * \param data to be verified
     * \param sig signature for verification
     * \return true if the data could be verified
     */
    bool verify_data(const ecdsa256::PublicKey& public_key, const ByteBuffer& data, const ByteBuffer& sig);

    /**
     * \brief generate a private key and the corresponding public key
     * \return generated key pair
     */
    ecdsa256::KeyPair generate_key_pair();

private:
    /// internal sign method using crypto++ private key
    EcdsaSignature sign_data(const PrivateKey& key, const ByteBuffer& data);

    /// internal verify method using crypto++ public key
    bool verify_data(const PublicKey& key, const ByteBuffer& data, const ByteBuffer& sig);

    /// create private key
    PrivateKey generate_private_key();

    /// derive public key from private key
    PublicKey generate_public_key(const PrivateKey&);

    /// adapt generic public key to internal structure
    PublicKey internal_public_key(const ecdsa256::PublicKey&);

    CryptoPP::AutoSeededRandomPool m_prng;
};

} // namespace security
} // namespace vanetza

#endif /* BACKEND_CRYPTOPP_HPP_JQWA9MLZ */

