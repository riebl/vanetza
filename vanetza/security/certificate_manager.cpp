#include <vanetza/security/certificate_manager.hpp>
#include <vanetza/security/secured_message.hpp>
#include <vanetza/security/signature.hpp>
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
    CryptoPP::AutoSeededRandomPool prng;
    std::string signature;
    std::string payload = buffer_cast_to_string(request.plaintext_payload);
    std::string header = buffer_cast_to_string(request.plaintext_pdu);

    std::string message = header + payload;

    // calculate signature
    // TODO (simon, markus): write Source and Sink classes for ByteBuffer
    CryptoPP::StringSink* string_sink = new CryptoPP::StringSink(signature);
    Signer signer(m_private_key);
    CryptoPP::SignerFilter* signer_filter = new CryptoPP::SignerFilter(prng, std::move(signer), string_sink);

    CryptoPP::StringSource( message, true,
                            signer_filter
    ); // StringSource

    EncapConfirm encap_confirm;
    encap_confirm.sec_payload = std::move(request.plaintext_payload);

    std::string signature_x = signature.substr(0, 32);
    std::string signature_s = signature.substr(32);

    EcdsaSignature ecdsa_signature;
    // set R
    Compressed_Lsb_Y_0 lsb;
    lsb.x = ByteBuffer(signature_x.begin(), signature_x.end());
    ecdsa_signature.R = std::move(lsb);
    // set s
    ByteBuffer trailer_field(signature_s.begin(), signature_s.end());
    ecdsa_signature.s = std::move(trailer_field);
    encap_confirm.sec_header.trailer_fields.push_back(ecdsa_signature);

    return std::move(encap_confirm);
}

DecapConfirm CertificateManager::verify_message(const DecapRequest& request)
{
    // TODO (simon,markus): check certificate

    // convert signature byte buffer to string
    SecuredMessage secured_header = std::move(request.sec_header);
    std::list<TrailerField> trailer_fields;

    trailer_fields = secured_header.trailer_fields;
    std::string signature;

    assert(!trailer_fields.empty());

    std::list<TrailerField>::iterator it = trailer_fields.begin();
    signature = serialize_trailer_field(*it);

    // convert message byte buffer to string
    std::string payload = buffer_cast_to_string(request.sec_payload);
    std::string pdu = buffer_cast_to_string(request.sec_pdu);

    std::string message = pdu + payload;

    // verify message signature
    bool result = false;
    CryptoPP::StringSource( signature+message, true,
                            new CryptoPP::SignatureVerificationFilter(Verifier(m_public_key), new CryptoPP::ArraySink((byte*)&result, sizeof(result)))
    );

    DecapConfirm decap_confirm;
    decap_confirm.plaintext_payload = std::move(request.sec_payload);
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

    ss.flush();

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
