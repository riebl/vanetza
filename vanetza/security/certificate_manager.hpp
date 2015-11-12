#ifndef CERTIFICATE_MANAGER_HPP
#define CERTIFICATE_MANAGER_HPP

#include <vanetza/geonet/shb_header.hpp>
#include <vanetza/geonet/extended_pdu.hpp>
#include <vanetza/common/byte_buffer.hpp>
#include <vanetza/security/secured_message.hpp>
#include <vanetza/security/decap_request.hpp>
#include <vanetza/security/encap_request.hpp>
#include <vanetza/security/decap_confirm.hpp>
#include <vanetza/security/encap_confirm.hpp>
#include <vanetza/security/trailer_field.hpp>
#include <vanetza/security/signature.hpp>
#include <cryptopp/osrng.h>
#include <cryptopp/oids.h>
#include <cryptopp/filters.h>
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
     * \tparam HEADER the extended header type
     * \param request the pdu and payload to sign
     * \return the signed pdu and payload
     */
    template<class HEADER>
    EncapConfirm<HEADER> sign_message(const EncapRequest<HEADER>& request);

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

    /** \brief serialize a ExtendedPdu to a std::string (for use with crypto++)
     *         using common and extended header for signing
     *
     * \tparam HEADER the extended header type
     * \param pdu the pdu to serialize
     * \return serialized representation of common and extended header
     */
    template<class HEADER>
    std::string serialize_extended_pdu(const geonet::ExtendedPdu<HEADER>& pdu);

    /** \brief serialize a ParsedPdu to a std::string (for use with crypto++)
     *         using common and extended header for signing
     *
     * \param pdu the pdu to serialize
     * \return serialized representation of common and extended header
     */
    std::string serialize_parsed_pdu(const geonet::ParsedPdu& pdu);

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

CertificateManager::CertificateManager()
{
    // generate private key
    CryptoPP::OID oid(CryptoPP::ASN1::secp256k1());
    CryptoPP::AutoSeededRandomPool prng;
    m_private_key.Initialize( prng, oid );
    assert(m_private_key.Validate(prng, 3));

    // generate public key
    m_private_key.MakePublicKey(m_public_key);
    assert(m_public_key.Validate(prng, 3));
}

template<class HEADER>
EncapConfirm<HEADER> CertificateManager::sign_message(const EncapRequest<HEADER>& request)
{
    CryptoPP::AutoSeededRandomPool prng;
    std::string signature;
    std::string payload = buffer_cast_to_string(request.plaintext_payload);
    std::string header = serialize_extended_pdu(request.plaintext_pdu);

    std::string message = header + payload;

    // calculate signature
    // TODO (simon, markus): write Source and Sink classes for ByteBuffer
    CryptoPP::StringSource( message, true,
                            new CryptoPP::SignerFilter(prng, Signer(m_private_key), new CryptoPP::StringSink( signature ) )
    ); // StringSource

    SecuredMessage sec_message;
    ByteBuffer trailer_field(signature.begin(), signature.end());
    EcdsaSignature ecdsa_signature;
    ecdsa_signature.s = trailer_field;
    // TODO (simon): add ECCPoint to R
    sec_message.trailer_fields.push_back(ecdsa_signature);

    geonet::ExtendedPdu<geonet::ShbHeader> extended_pdu = request.plaintext_pdu;
    extended_pdu.secured() = sec_message;

    EncapConfirm<HEADER> encap_confirm;
    encap_confirm.sec_pdu = extended_pdu;
    encap_confirm.sec_payload = request.plaintext_payload;

    return std::move(encap_confirm);
}

DecapConfirm CertificateManager::verify_message(const DecapRequest& request)
{
    // convert signature byte buffer to string
    boost::optional<SecuredMessage> secured_header = request.sec_pdu.secured;
    std::list<TrailerField> trailer_fields;
    assert(secured_header);

    trailer_fields = secured_header.get().trailer_fields;
    std::string signature;

    assert(trailer_fields.begin() != trailer_fields.end());

    std::list<TrailerField>::iterator it = trailer_fields.begin();
    signature = serialize_trailer_field(*it);

    // build decap result object
    geonet::ParsedPdu parsed_pdu;
    parsed_pdu.basic = request.sec_pdu.basic;
    parsed_pdu.common = request.sec_pdu.common;
    parsed_pdu.extended = request.sec_pdu.extended;

    // convert message byte buffer to string
    ByteBuffer message_buffer = request.sec_payload;
    std::string payload = buffer_cast_to_string(message_buffer);
    std::string header = serialize_parsed_pdu(parsed_pdu);

    std::string message = header + payload;

    // verify message signature
    bool result = false;
    CryptoPP::StringSource( signature+message, true,
                            new CryptoPP::SignatureVerificationFilter(Verifier(m_public_key), new CryptoPP::ArraySink( (byte*)&result, sizeof(result) ))
    );

    DecapConfirm decap_confirm;
    decap_confirm.plaintext_pdu = parsed_pdu;
    decap_confirm.plaintext_payload = request.sec_payload;
    if (result) {
        decap_confirm.report = ReportType::Success;
    } else {
        decap_confirm.report = ReportType::False_Signature;
    }

    return std::move(decap_confirm);
}

std::string CertificateManager::serialize_trailer_field(const TrailerField& field)
{
    std::stringstream ss;
    OutputArchive ar(ss);
    serialize(ar, field);

    return std::move(ss.str());
}

template<class HEADER>
std::string CertificateManager::serialize_extended_pdu(const geonet::ExtendedPdu<HEADER>& pdu)
{
    std::stringstream ss;
    OutputArchive ar(ss);
    serialize(pdu.common(), ar);
    serialize(pdu.extended(), ar);

    return std::move(ss.str());
}

std::string CertificateManager::serialize_parsed_pdu(const geonet::ParsedPdu& pdu)
{
    std::stringstream ss;
    OutputArchive ar(ss);
    serialize(pdu.common, ar);
    serialize(pdu.extended, ar);

    return std::move(ss.str());
}

const std::string CertificateManager::buffer_cast_to_string(const ByteBuffer& buffer)
{
    std::stringstream oss;
    std::copy(buffer.begin(), buffer.end(), std::ostream_iterator<ByteBuffer::value_type>(oss));
    return std::move(oss.str());
}

} // namespace security
} // namespace vanetza

#endif // CERTIFICATE_MANAGER_HPP
