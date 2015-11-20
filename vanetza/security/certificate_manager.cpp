#include <vanetza/security/ecc_point.hpp>
#include <vanetza/security/basic_elements.hpp>
#include <vanetza/security/certificate_manager.hpp>
#include <vanetza/security/secured_message.hpp>
#include <vanetza/security/signature.hpp>
#include <vanetza/security/payload.hpp>
#include <cryptopp/osrng.h>
#include <cryptopp/oids.h>
#include <cryptopp/filters.h>

namespace vanetza
{
namespace security
{

CertificateManager::CertificateManager()
{
    // generate private key
    CryptoPP::OID oid(CryptoPP::ASN1::secp256r1());
    CryptoPP::AutoSeededRandomPool prng;
    m_private_key.Initialize(prng, oid);
    assert(m_private_key.Validate(prng, 3));

    // generate public key
    m_private_key.MakePublicKey(m_public_key);
    assert(m_public_key.Validate(prng, 3));
}

EncapConfirm CertificateManager::sign_message(const EncapRequest& request)
{
    EncapConfirm encap_confirm;
    // set secured message data
    encap_confirm.sec_packet.payload.type = PayloadType::Signed;
    encap_confirm.sec_packet.payload.buffer = std::move(request.plaintext_payload);
    // set header field data
    // TODO: header_fieds.signerInfo.type = certificate, fill in certificate or add certificate_digest_with_sha256
    encap_confirm.sec_packet.header_fields.push_back(get_time());
    encap_confirm.sec_packet.header_fields.push_back((uint16_t) 36); // according to TS 102 965, and ITS-AID_AssignedNumbers

    // create trailer field to get the size in bytes
    size_t trailer_field_size = 0;
    {
        security::EcdsaSignature temp_signature;
        temp_signature.s.resize(32);
        Compressed_Lsb_Y_0 compressed_Lsb_Y_0;
        compressed_Lsb_Y_0.x.resize(32);
        temp_signature.R = compressed_Lsb_Y_0;

        security::TrailerField temp_trailer_field = temp_signature;

        trailer_field_size = get_size(temp_trailer_field);
    }

    CryptoPP::AutoSeededRandomPool prng;
    std::string signature;
    std::string payload = buffer_cast_to_string(
            convert_for_signing(encap_confirm.sec_packet, TrailerFieldType::Signature, trailer_field_size));
    std::string header = buffer_cast_to_string(request.plaintext_pdu);

    std::string message = header + payload;

    // calculate signature
    // TODO (simon, markus): write Source and Sink classes for ByteBuffer
    CryptoPP::StringSink* string_sink = new CryptoPP::StringSink(signature);
    Signer signer(m_private_key);
    CryptoPP::SignerFilter* signer_filter = new CryptoPP::SignerFilter(prng, std::move(signer), string_sink);

    // Covered by signature:
    //      SecuredMessage: protocol_version, header_fields (incl. its length), payload_field, trailer_field.trailer_field_type
    //      CommonHeader: complete
    //      ExtendedHeader: complete
    // p. 27 in TS 103 097 v1.2.1
    CryptoPP::StringSource( message, true, signer_filter); // StringSource

    std::string signature_x = signature.substr(0, 32);
    std::string signature_s = signature.substr(32);

    EcdsaSignature ecdsa_signature;
    // set R
    Compressed_Lsb_Y_0 lsb;
    lsb.x = ByteBuffer(signature_x.begin(), signature_x.end());
    ecdsa_signature.R = std::move(lsb);
    // set s
    ByteBuffer trailer_field_buffer(signature_s.begin(), signature_s.end());
    ecdsa_signature.s = std::move(trailer_field_buffer);
    encap_confirm.sec_packet.trailer_fields.push_back(ecdsa_signature);

    TrailerField trailer_field = ecdsa_signature;
    assert(get_size(trailer_field) == trailer_field_size);

    return std::move(encap_confirm);
}

DecapConfirm CertificateManager::verify_message(const DecapRequest& request)
{
    // TODO (simon,markus): check certificate

    // convert signature byte buffer to string
    SecuredMessage secured_message = std::move(request.sec_packet);
    std::list<TrailerField> trailer_fields;

    trailer_fields = secured_message.trailer_fields;
    std::string signature;

    assert(!trailer_fields.empty());

    std::list<TrailerField>::iterator it = trailer_fields.begin();
    signature = buffer_cast_to_string(extract_signature_buffer(*it));

    // convert message byte buffer to string
    std::string payload = buffer_cast_to_string(convert_for_signing(secured_message, get_type(*it), get_size(*it)));
    std::string pdu = buffer_cast_to_string(request.sec_pdu);

    std::string message = pdu + payload;

    // verify message signature
    bool result = false;
    CryptoPP::StringSource( signature+message, true,
                            new CryptoPP::SignatureVerificationFilter(Verifier(m_public_key), new CryptoPP::ArraySink((byte*)&result, sizeof(result)))
    );

    DecapConfirm decap_confirm;
    decap_confirm.plaintext_payload = std::move(request.sec_packet.payload.buffer);
    if (result) {
        decap_confirm.report = ReportType::Success;
    } else {
        decap_confirm.report = ReportType::False_Signature;
    }

    return std::move(decap_confirm);
}

const std::string CertificateManager::buffer_cast_to_string(const ByteBuffer& buffer)
{
    std::stringstream oss;
    std::copy(buffer.begin(), buffer.end(), std::ostream_iterator<ByteBuffer::value_type>(oss));
    return std::move(oss.str());
}

Time64 CertificateManager::get_time()
{
    return ((Time64) m_time_now.raw()) * 1000 * 1000;
}

} // namespace security
} // namespace vanetza
