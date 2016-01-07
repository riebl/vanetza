#include <vanetza/security/ecc_point.hpp>
#include <vanetza/security/basic_elements.hpp>
#include <vanetza/security/certificate_manager.hpp>
#include <vanetza/security/secured_message.hpp>
#include <vanetza/security/signature.hpp>
#include <vanetza/security/payload.hpp>
#include <cryptopp/osrng.h>
#include <cryptopp/oids.h>
#include <cryptopp/filters.h>
#include <cryptopp/hex.h>
#include <boost/format.hpp>

namespace vanetza
{
namespace security
{

CertificateManager::CertificateManager(const geonet::Timestamp& time_now) : m_time_now(time_now)
{
    // generate key pair
    m_root_key_pair = generate_key_pair();

    // TODO(aaron,robert): this is random for now, has to be calculated later (for HashedId8 calculation see TS 103 097 v1.2.1 section 4.2.12)
    m_root_certificate_hash = HashedId8{ 0x17, 0x5c, 0x33, 0x48, 0x25, 0xdc, 0x7f, 0xab };
}

EncapConfirm CertificateManager::sign_message(const EncapRequest& request)
{
    // create certificate and key pair
    KeyPair key_pair = generate_key_pair();
    Certificate temp_certificate = generate_certificate(key_pair);

    EncapConfirm encap_confirm;
    // set secured message data
    encap_confirm.sec_packet.payload.type = PayloadType::Signed;
    encap_confirm.sec_packet.payload.buffer = std::move(request.plaintext_payload);
    // set header field data
    encap_confirm.sec_packet.header_fields.push_back(get_time()); // generation_time
    encap_confirm.sec_packet.header_fields.push_back((uint16_t) 36); // its_aid, according to TS 102 965, and ITS-AID_AssignedNumbers

    SignerInfo signer_info = temp_certificate;
    encap_confirm.sec_packet.header_fields.push_back(signer_info);

    // create trailer field to get the size in bytes
    size_t trailer_field_size = 0;
    {
        security::EcdsaSignature temp_signature;
        temp_signature.s.resize(field_size(PublicKeyAlgorithm::Ecdsa_Nistp256_With_Sha256));
        X_Coordinate_Only x_coordinate_only;
        x_coordinate_only.x.resize(field_size(PublicKeyAlgorithm::Ecdsa_Nistp256_With_Sha256));
        temp_signature.R = x_coordinate_only;

        security::TrailerField temp_trailer_field = temp_signature;

        trailer_field_size = get_size(temp_trailer_field);
    }

    // Covered by signature:
    //      SecuredMessage: protocol_version, header_fields (incl. its length), payload_field, trailer_field.trailer_field_type
    //      CommonHeader: complete
    //      ExtendedHeader: complete
    // p. 27 in TS 103 097 v1.2.1
    ByteBuffer data_buffer = convert_for_signing(encap_confirm.sec_packet, trailer_field_size);

    TrailerField trailer_field = sign_data(key_pair.private_key, data_buffer);
    assert(get_size(trailer_field) == trailer_field_size);

    encap_confirm.sec_packet.trailer_fields.push_back(trailer_field);

    return std::move(encap_confirm);
}

DecapConfirm CertificateManager::verify_message(const DecapRequest& request)
{
    boost::optional<Certificate> certificate;
    for (auto& field : request.sec_packet.header_fields) {
        if (get_type(field) == HeaderFieldType::Signer_Info) {
            assert(SignerInfoType::Certificate == get_type(boost::get<SignerInfo>(field)));
            certificate = boost::get<Certificate>(boost::get<SignerInfo>(field));
            break;
        }
    }

    DecapConfirm decap_confirm;
    if (!certificate) {
        decap_confirm.report = ReportType::Signer_Certificate_Not_Found;
        return decap_confirm;
    }

    PublicKey public_key = get_public_key_from_certificate(certificate.get());

    // if certificate could not be verified return correct ReportType
    if (!check_certificate(certificate.get())) {
        decap_confirm.report = ReportType::Invalid_Certificate;
        return decap_confirm;
    }

    // convert signature byte buffer to string
    SecuredMessage secured_message = std::move(request.sec_packet);
    std::list<TrailerField> trailer_fields;

    trailer_fields = secured_message.trailer_fields;

    assert(!trailer_fields.empty());

    std::list<TrailerField>::iterator it = trailer_fields.begin();

    // check Signature
    boost::optional<ByteBuffer> signature = extract_signature_buffer(*it);
    if (!signature) {
        decap_confirm.report = ReportType::False_Signature;
        return decap_confirm;
    }

    // convert message byte buffer to string
    ByteBuffer message = std::move(signature.get());
    ByteBuffer payload = convert_for_signing(secured_message, get_size(*it));
    message.insert(message.end(), payload.begin(), payload.end());

    // result of verify function
    bool result = verify_data(public_key, std::move(message));

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

Certificate CertificateManager::generate_certificate(const CertificateManager::KeyPair& key_pair)
{
    // create certificate
    Certificate certificate;

    // section 6.1 in TS 103 097 v1.2.1
    certificate.signer_info = m_root_certificate_hash;

    // section 6.3 in TS 103 097 v1.2.1
    certificate.subject_info.subject_type = SubjectType::Authorization_Ticket;
    // section 7.4.2 in TS 103 097 v1.2.1, subject_name implicit empty

    // set assurance level
    certificate.subject_attributes.push_back(SubjectAssurance(0x00));

    // section 7.4.1 in TS 103 097 v1.2.1
    // set subject attributes
    // set the verification_key
    Uncompressed coordinates;
    {
        coordinates.x.resize(32);
        coordinates.y.resize(32);
        key_pair.public_key.GetPublicElement().x.Encode(coordinates.x.data(), coordinates.x.size());
        key_pair.public_key.GetPublicElement().y.Encode(coordinates.y.data(), coordinates.y.size());

        assert(CryptoPP::SHA256::DIGESTSIZE == coordinates.x.size());
        assert(CryptoPP::SHA256::DIGESTSIZE == coordinates.y.size());
    }
    EccPoint ecc_point = coordinates;
    ecdsa_nistp256_with_sha256 ecdsa;
    ecdsa.public_key = ecc_point;
    VerificationKey verification_key;
    verification_key.key = ecdsa;
    certificate.subject_attributes.push_back(verification_key);

    // section 6.7 in TS 103 097 v1.2.1
    // set validity restriction
    StartAndEndValidity start_and_end;
    start_and_end.start_validity = get_time_in_seconds();
    start_and_end.end_validity = get_time_in_seconds() + 3600 * 24; // add 1 day
    certificate.validity_restriction.push_back(start_and_end);

    // set signature
    ByteBuffer data_buffer = convert_for_signing(certificate);

    // Covered by signature:
    //      version, signer_field, subject_info,
    //      subject_attributes + length,
    //      validity_restriction + length
    // section 7.4 in TS 103 097 v1.2.1
    certificate.signature = std::move(sign_data(m_root_key_pair.private_key, data_buffer));

    return std::move(certificate);
}

CertificateManager::KeyPair CertificateManager::generate_key_pair()
{
    KeyPair key_pair;
    // generate private key
    CryptoPP::OID oid(CryptoPP::ASN1::secp256r1());
    CryptoPP::AutoSeededRandomPool prng;
    key_pair.private_key.Initialize(prng, oid);
    assert(key_pair.private_key.Validate(prng, 3));

    // generate public key
    key_pair.private_key.MakePublicKey(key_pair.public_key);
    assert(key_pair.public_key.Validate(prng, 3));

    return key_pair;
}

bool CertificateManager::check_certificate(const Certificate& certificate)
{
    // check validity restriction
    for (auto& restriction : certificate.validity_restriction) {
        ValidityRestriction validity_restriction = restriction;

        ValidityRestrictionType type = get_type(validity_restriction);
        if (type == ValidityRestrictionType::Time_Start_And_End) {
            // change start and end time of certificate validity
            StartAndEndValidity start_and_end = boost::get<StartAndEndValidity>(validity_restriction);
            // check if certificate validity restriction timestamps are logically correct
            if (start_and_end.start_validity >= start_and_end.end_validity) {
                certificate_invalid(CertificateInvalidReason::BROKEN_TIME_PERIOD);
                return false;
            }
            // check if certificate is premature or outdated
            if (get_time_in_seconds() < start_and_end.start_validity || get_time_in_seconds() > start_and_end.end_validity) {
                certificate_invalid(CertificateInvalidReason::OFF_TIME_PERIOD);
                return false;
            }
        }
    }

    // check if subject_name is empty
    if (0 != certificate.subject_info.subject_name.size()) {
        certificate_invalid(CertificateInvalidReason::INVALID_NAME);
        return false;
    }

    // check signer info
    if(get_type(certificate.signer_info) == SignerInfoType::Certificate_Digest_With_SHA256) {
        HashedId8 signer_hash = boost::get<HashedId8>(certificate.signer_info);
        if(signer_hash != m_root_certificate_hash) {
            certificate_invalid(CertificateInvalidReason::INVALID_ROOT_HASH);
            return false;
        }
    }

    // create ByteBuffer of Signature
    boost::optional<ByteBuffer> sig = extract_signature_buffer(certificate.signature);
    if (!sig) {
        certificate_invalid(CertificateInvalidReason::MISSING_SIGNATURE);
        return false;
    }

    // create buffer of certificate
    ByteBuffer cert = convert_for_signing(certificate);

    // append certificate to signature buffer
    ByteBuffer sig_and_cert = sig.get();
    sig_and_cert.insert(sig_and_cert.end(), cert.begin(), cert.end());

    if (!verify_data(m_root_key_pair.public_key, sig_and_cert)) {
        certificate_invalid(CertificateInvalidReason::INVALID_SIGNATURE);
        return false;
    }

    return true;
}

CertificateManager::PublicKey CertificateManager::get_public_key_from_certificate(const Certificate& certificate)
{
    // generate public key from certificate data (x_coordinate + y_coordinate)
    boost::optional<Uncompressed> public_key_coordinates;
    for (auto& attribute : certificate.subject_attributes) {
        if (get_type(attribute) == SubjectAttributeType::Verification_Key) {
            public_key_coordinates = boost::get<Uncompressed>(boost::get<ecdsa_nistp256_with_sha256>(boost::get<VerificationKey>(attribute).key).public_key);
            break;
        }
    }

    assert(public_key_coordinates.is_initialized());

    std::stringstream ss;
    for (uint8_t b : public_key_coordinates.get().x) {
        ss << boost::format("%02x") % (int)b;
    }
    std::string x_coordinate = ss.str();
    ss.str("");
    for (uint8_t b : public_key_coordinates.get().y) {
        ss << boost::format("%02x") % (int)b;
    }
    std::string y_coordinate = ss.str();

    CryptoPP::HexDecoder x_decoder, y_decoder;
    x_decoder.Put((byte*)x_coordinate.c_str(), x_coordinate.length());
    x_decoder.MessageEnd();
    y_decoder.Put((byte*)y_coordinate.c_str(), y_coordinate.length());
    y_decoder.MessageEnd();

    size_t len = x_decoder.MaxRetrievable();
    assert(len == CryptoPP::SHA256::DIGESTSIZE);
    len = y_decoder.MaxRetrievable();
    assert(len == CryptoPP::SHA256::DIGESTSIZE);

    CryptoPP::ECP::Point q;
    q.identity = false;
    q.x.Decode(x_decoder, len);
    q.y.Decode(y_decoder, len);

    PublicKey public_key;
    public_key.Initialize(CryptoPP::ASN1::secp256r1(), q);
    CryptoPP::AutoSeededRandomPool prng;
    assert(public_key.Validate(prng, 3));

    return public_key;
}

EcdsaSignature CertificateManager::sign_data(const PrivateKey& private_key, ByteBuffer data_buffer)
{
    CryptoPP::AutoSeededRandomPool prng;
    std::string signature;

    std::string data = buffer_cast_to_string(data_buffer);

    // calculate signature
    // TODO (simon, markus): write Source and Sink classes for ByteBuffer
    CryptoPP::StringSink* string_sink = new CryptoPP::StringSink(signature);
    Signer signer(private_key);
    CryptoPP::SignerFilter* signer_filter = new CryptoPP::SignerFilter(prng, std::move(signer), string_sink);

    CryptoPP::StringSource( data, true, signer_filter); // StringSource

    std::string signature_x = signature.substr(0, 32);
    std::string signature_s = signature.substr(32);

    EcdsaSignature ecdsa_signature;
    // set R
    X_Coordinate_Only coordinate;
    coordinate.x = ByteBuffer(signature_x.begin(), signature_x.end());
    ecdsa_signature.R = std::move(coordinate);
    // set s
    ByteBuffer trailer_field_buffer(signature_s.begin(), signature_s.end());
    ecdsa_signature.s = std::move(trailer_field_buffer);

    return ecdsa_signature;
}

bool CertificateManager::verify_data(const PublicKey& public_key, ByteBuffer data_buffer)
{
    std::string data_string = buffer_cast_to_string(data_buffer);
    // verify certificate signature
    bool result = false;
    CryptoPP::StringSource( data_string, true,
                            new CryptoPP::SignatureVerificationFilter(Verifier(public_key), new CryptoPP::ArraySink((byte*)&result, sizeof(result)))
    );

    return result;
}

Time64 CertificateManager::get_time()
{
    return ((Time64) m_time_now.raw()) * 1000 * 1000;
}

Time32 CertificateManager::get_time_in_seconds()
{
    return m_time_now.raw();
}

} // namespace security
} // namespace vanetza
