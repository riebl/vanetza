#ifndef CERTIFICATE_MANAGER_HPP
#define CERTIFICATE_MANAGER_HPP

#include <vanetza/geonet/extended_pdu.hpp>
#include <vanetza/geonet/header_variant.hpp>
#include <vanetza/common/byte_buffer.hpp>
#include <vanetza/security/decap_request.hpp>
#include <vanetza/security/encap_request.hpp>
#include <vanetza/security/decap_confirm.hpp>
#include <vanetza/security/encap_confirm.hpp>
#include <vanetza/security/trailer_field.hpp>
#include <cryptopp/eccrypto.h>
#include <cryptopp/sha.h>
#include <string>

namespace vanetza
{
namespace security
{

/** \brief A Manager to handle Certificates using Crypto++
 *  \TODO: move function implementations in source file + rename to CryptoPPCertManager
 *         create a base class
 */
class CertificateManager
{
public:
    typedef CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PrivateKey PrivateKey;
    typedef CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::PublicKey PublicKey;
    typedef CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::Signer Signer;
    typedef CryptoPP::ECDSA<CryptoPP::ECP, CryptoPP::SHA256>::Verifier Verifier;

    CertificateManager();

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

    /** \brief serialize a TrailerField to a std::string (for use with crypto++)
     *
     * \param field the TrailerField to serialize
     * \return serialized representation of the given TrailerField
     */
    std::string serialize_trailer_field(const TrailerField& field);

    /** \brief cast ByteBuffer to std::string (for use with crypto++)
     *
     * \param buffer the ByteBuffer to convert
     * \return the std::string representation
     *
     */
    const std::string buffer_cast_to_string(const ByteBuffer& buffer);

private:
    PrivateKey m_private_key;
    PublicKey m_public_key;
};

} // namespace security
} // namespace vanetza

#endif // CERTIFICATE_MANAGER_HPP
