#ifndef CERTIFICATE_MANAGER_HPP
#define CERTIFICATE_MANAGER_HPP

#include <vanetza/geonet/extended_pdu.hpp>
#include <vanetza/geonet/header_variant.hpp>
#include <vanetza/geonet/timestamp.hpp>
#include <vanetza/common/byte_buffer.hpp>
#include <vanetza/security/basic_elements.hpp>
#include <vanetza/security/decap_request.hpp>
#include <vanetza/security/encap_request.hpp>
#include <vanetza/security/decap_confirm.hpp>
#include <vanetza/security/encap_confirm.hpp>
#include <vanetza/security/trailer_field.hpp>
#include <vanetza/security/certificate.hpp>
#include <cryptopp/eccrypto.h>
#include <cryptopp/sha.h>
#include <string>

namespace vanetza
{
namespace security
{

/** \brief A Manager to handle Certificates using Crypto++
 *  \TODO: rename to CryptoPPCertManager
 *         create a base class
 */
class CertificateManager
{
public:
    typedef CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PrivateKey PrivateKey;
    typedef CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PublicKey PublicKey;
    typedef CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::Signer Signer;
    typedef CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::Verifier Verifier;

    struct KeyPair
    {
        PrivateKey private_key;
        PublicKey public_key;
    };

    CertificateManager(const geonet::Timestamp& time_now);

    /** \brief use common header, extended header and payload to create a signature
     *         write signature to pdu.SecuredMessage
     *
     * \param request the pdu and payload to sign
     * \return the signed pdu and payload
     */
    EncapConfirm sign_message(const EncapRequest& request);

    /** \brief use common header, extended header and payload to create a signature
     *         check with given signature in SecuredMessage
     *
     * \param request the pdu and payload to verify
     * \return the verified pdu, payload and the ReportType
     */
    DecapConfirm verify_message(const DecapRequest& request);

    /** \brief cast ByteBuffer to std::string (for use with crypto++)
     *
     * \param buffer the ByteBuffer to convert
     * \return the std::string representation
     *
     */
    const std::string buffer_cast_to_string(const ByteBuffer& buffer);

    /** \brief generate a certificate
     *
     * \param key_pair keys used to create the certificate
     * \return Certificate
     */
    Certificate generate_certificate(const KeyPair& key_pair);

    /** \brief generate a private key and the corresponding public key
     *
     * \return KeyPair
     */
     KeyPair generate_key_pair();

private:
     /** \brief check the certificate
     *
     * \param certificate to verify
     * \return true if certificate could be verified
     */
    bool check_certificate(const Certificate& certificate);

    /** \brief extract public key from certificate
     *
     * \param certificate
     * \return PublicKey
     */
    PublicKey get_public_key_from_certificate(const Certificate& certificate);

    /** \brief get the current (system) time in microseconds
     *
     * \return Time64
     */
    Time64 get_time();

    /** \brief get the current (system) time in seconds
     *
     * \return Time32
     */
    Time32 get_time_in_seconds();

    /** \brief generate EcdsaSignature, for given data with private_key
     *
     * \param private_key
     * \param data_buffer
     * \return EcdsaSignature
     */
    EcdsaSignature sign_data(const PrivateKey& private_key, ByteBuffer data_buffer);

    /** \brief checks if the data_buffer can be verified with the public_key
     *
     * \param public_key
     * \param data_buffer: data to be verified
     * \return true if the data_buffer could be verified
     *
     */
    bool verify_data(const PublicKey& public_key, ByteBuffer data_buffer);

    KeyPair m_root_key_pair;
    HashedId8 m_root_certificate_hash;
    const geonet::Timestamp& m_time_now;
};

} // namespace security
} // namespace vanetza

#endif // CERTIFICATE_MANAGER_HPP
