#ifndef BACKEND_CRYPTOPP_HPP_JQWA9MLZ
#define BACKEND_CRYPTOPP_HPP_JQWA9MLZ

#include <vanetza/security/backend.hpp>
#include <cryptopp/eccrypto.h>
#include <cryptopp/osrng.h>
#include <cryptopp/sha.h>

namespace vanetza
{
namespace security
{

class BackendCryptoPP : public Backend
{
public:
    using Ecdsa256 = CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>;
    using Ecdsa384 = CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA384>;

    static constexpr auto backend_name = "CryptoPP";

    BackendCryptoPP();

    /// \see Backend::sign_data
    EcdsaSignature sign_data(const ecdsa256::PrivateKey& private_key, const ByteBuffer& data_buffer) override;
    Signature sign_data(const PrivateKey&, const ByteBuffer& data) override;

    /// \see Backend::verify_data
    bool verify_data(const ecdsa256::PublicKey& public_key, const ByteBuffer& data, const EcdsaSignature& sig) override;

    /// \see Backend::verify_digest
    bool verify_digest(const PublicKey&, const ByteBuffer& digest, const Signature&) override;

    /// \see Backend::decompress_point
    boost::optional<Uncompressed> decompress_point(const EccPoint& ecc_point) override;

    /// \see Backend::calculate_hash
    ByteBuffer calculate_hash(KeyType, const ByteBuffer&) override;

    /**
     * \brief generate a private key and the corresponding public key
     * \return generated key pair
     */
    ecdsa256::KeyPair generate_key_pair();

private:
    /// internal sign method using crypto++ private key
    EcdsaSignature sign_data(const Ecdsa256::PrivateKey& key, const ByteBuffer& data);

    /// internal verify method using crypto++ public key
    bool verify_data(const Ecdsa256::PublicKey& key, const ByteBuffer& data, const ByteBuffer& sig);

    /// create private key
    Ecdsa256::PrivateKey generate_private_key();

    /// derive public key from private key
    Ecdsa256::PublicKey generate_public_key(const Ecdsa256::PrivateKey&);

    /// adapt generic public key to internal structure
    Ecdsa256::PublicKey internal_public_key(const ecdsa256::PublicKey&);

    /// adapt generic private key to internal structure
    Ecdsa256::PrivateKey internal_private_key(const ecdsa256::PrivateKey&);

    CryptoPP::AutoSeededRandomPool m_prng;
};

} // namespace security
} // namespace vanetza

#endif /* BACKEND_CRYPTOPP_HPP_JQWA9MLZ */
