#include <vanetza/security/ecc_point.hpp>
#include <vanetza/security/basic_elements.hpp>
#include <vanetza/security/certificate_manager.hpp>
#include <vanetza/security/secured_message.hpp>
#include <vanetza/security/signature.hpp>
#include <vanetza/security/payload.hpp>
#include <cryptopp/osrng.h>
#include <cryptopp/oids.h>
#include <chrono>
#include <future>

namespace vanetza
{
namespace security
{

CertificateManager::CertificateManager(const Clock::time_point& time_now) :
    m_time_now(time_now), m_root_key_pair(get_root_key_pair()),
    m_root_certificate_hash(HashedId8 { 0x17, 0x5c, 0x33, 0x48, 0x25, 0xdc, 0x7f, 0xab }),
    m_own_key_pair(m_crypto_backend.generate_key_pair()),
    m_own_certificate(generate_certificate(m_own_key_pair)),
    m_sign_deferred(false)
{
    // TODO: root certifiate hash is arbitrarily chosen for now
    // It has to be calculated later, see TS 103 097 v1.2.1 section 4.2.12 for HashedId8
}

EncapConfirm CertificateManager::sign_message(const EncapRequest& request)
{
    // renew certificate if necessary
    for (auto& validity_restriction : m_own_certificate.validity_restriction) {
        auto start_and_end = boost::get<StartAndEndValidity>(&validity_restriction);
        if (start_and_end && start_and_end->end_validity < get_time_in_seconds() + 3600) {
            m_own_certificate = generate_certificate(m_own_key_pair);
            break;
        }
    }

    EncapConfirm encap_confirm;
    // set secured message data
    encap_confirm.sec_packet.payload.type = PayloadType::Signed;
    encap_confirm.sec_packet.payload.data = std::move(request.plaintext_payload);
    // set header field data
    encap_confirm.sec_packet.header_fields.push_back(get_time()); // generation_time
    encap_confirm.sec_packet.header_fields.push_back((uint16_t) 36); // its_aid, according to TS 102 965, and ITS-AID_AssignedNumbers

    SignerInfo signer_info = m_own_certificate;
    encap_confirm.sec_packet.header_fields.push_back(signer_info);

    // create trailer field to get the size in bytes
    size_t trailer_field_size = 0;
    size_t signature_size = 0;
    {
        security::EcdsaSignature temp_signature;
        temp_signature.s.resize(field_size(PublicKeyAlgorithm::Ecdsa_Nistp256_With_Sha256));
        X_Coordinate_Only x_coordinate_only;
        x_coordinate_only.x.resize(field_size(PublicKeyAlgorithm::Ecdsa_Nistp256_With_Sha256));
        temp_signature.R = x_coordinate_only;

        security::TrailerField temp_trailer_field = temp_signature;

        trailer_field_size = get_size(temp_trailer_field);
        signature_size = get_size(temp_signature);
    }

    // Covered by signature:
    //      SecuredMessage: protocol_version, header_fields (incl. its length), payload_field, trailer_field.trailer_field_type
    //      CommonHeader: complete
    //      ExtendedHeader: complete
    // p. 27 in TS 103 097 v1.2.1
    if (m_sign_deferred) {
        auto future = std::async(std::launch::deferred, [=]() {
            ByteBuffer data = convert_for_signing(encap_confirm.sec_packet, trailer_field_size);
            return m_crypto_backend.sign_data(m_own_key_pair.private_key, data);
        });
        EcdsaSignatureFuture signature(future.share(), signature_size);
        encap_confirm.sec_packet.trailer_fields.push_back(signature);
    } else {
        ByteBuffer data_buffer = convert_for_signing(encap_confirm.sec_packet, trailer_field_size);
        TrailerField trailer_field = m_crypto_backend.sign_data(m_own_key_pair.private_key, data_buffer);
        assert(get_size(trailer_field) == trailer_field_size);
        encap_confirm.sec_packet.trailer_fields.push_back(trailer_field);
    }

    return encap_confirm;
}

DecapConfirm CertificateManager::verify_message(const DecapRequest& request)
{
    DecapConfirm decap_confirm;

    const SecuredMessage& secured_message = request.sec_packet;
    // set the payload, when verfiy != success, we need this for NON_STRICT packet handling
    decap_confirm.plaintext_payload = request.sec_packet.payload.data;

    if (PayloadType::Signed != secured_message.payload.type) {
        decap_confirm.report = ReportType::Unsigned_Message;
        return decap_confirm;
    }

    if (SecuredMessage().protocol_version() != secured_message.protocol_version()) {
        decap_confirm.report = ReportType::Incompatible_Protocol;
        return decap_confirm;
    }

    boost::optional<const Certificate&> certificate;
    boost::optional<Time64> generation_time;
    for (auto& field : request.sec_packet.header_fields) {
        switch (get_type(field)) {
        case HeaderFieldType::Signer_Info:
            switch (get_type(boost::get<SignerInfo>(field))) {
            case SignerInfoType::Certificate:
                certificate = boost::get<Certificate>(boost::get<SignerInfo>(field));
                break;
            case SignerInfoType::Self:
            case SignerInfoType::Certificate_Digest_With_SHA256:
            case SignerInfoType::Certificate_Digest_With_Other_Algorithm:
                break;
            case SignerInfoType::Certificate_Chain:
                //TODO check if Certificate_Chain is inconsistant
                break;
            default:
                decap_confirm.report = ReportType::Unsupported_Signer_Identifier_Type;
                return decap_confirm;
                break;
            }
            break;
        case HeaderFieldType::Generation_Time:
            generation_time = boost::get<Time64>(field);
            break;
        default:
            break;
        }
    }

    if (!certificate) {
        decap_confirm.report = ReportType::Signer_Certificate_Not_Found;
        return decap_confirm;
    }

    if (!generation_time || (generation_time && (get_time() < generation_time.get()))) {
        decap_confirm.report = ReportType::Invalid_Timestamp;
        return decap_confirm;
    }

    // TODO check Duplicate_Message, Invalid_Mobility_Data, Unencrypted_Message, Decryption_Error

    boost::optional<BackendCryptoPP::PublicKey> public_key = get_public_key_from_certificate(certificate.get());

    // public key could not be extracted
    if (!public_key) {
        decap_confirm.report = ReportType::Invalid_Certificate;
        return decap_confirm;
    }

    // if certificate could not be verified return correct ReportType
    CertificateValidity cert_validity = check_certificate(*certificate);
    if (!cert_validity) {
        decap_confirm.report = ReportType::Invalid_Certificate;
        decap_confirm.certificate_validity = cert_validity;
        return decap_confirm;
    }

    // TODO check if Revoked_Certificate

    // convert signature byte buffer to string
    auto& trailer_fields = secured_message.trailer_fields;

    if (trailer_fields.empty()) {
        decap_confirm.report = ReportType::Unsigned_Message;
        return decap_confirm;
    }

    boost::optional<Signature> signature;
    for (auto& field : trailer_fields) {
        if (TrailerFieldType::Signature == get_type(field)) {
            if (PublicKeyAlgorithm::Ecdsa_Nistp256_With_Sha256 == get_type(boost::get<Signature>(field))) {
                signature = boost::get<Signature>(field);
                break;
            }
        }
    }

    // check Signature
    if (!signature) {
        decap_confirm.report = ReportType::Unsigned_Message;
        return decap_confirm;
    }

    // check the size of signature.R and siganture.s
    auto ecdsa = extract_ecdsa_signature(signature.get());
    ByteBuffer signature_buffer = extract_signature_buffer(signature.get());
    if (field_size(PublicKeyAlgorithm::Ecdsa_Nistp256_With_Sha256) * 2 != signature_buffer.size() ||
        field_size(PublicKeyAlgorithm::Ecdsa_Nistp256_With_Sha256) != ecdsa.get().s.size()) {
        decap_confirm.report = ReportType::False_Signature;
        return decap_confirm;
    }

    // convert message byte buffer to string
    ByteBuffer payload = convert_for_signing(secured_message, get_size(TrailerField(signature.get())));

    // result of verify function
    bool result = m_crypto_backend.verify_data(public_key.get(), payload, signature_buffer);

    if (result) {
        decap_confirm.report = ReportType::Success;
    } else {
        decap_confirm.report = ReportType::False_Signature;
    }

    return decap_confirm;
}

Certificate CertificateManager::generate_certificate(const BackendCryptoPP::KeyPair& key_pair)
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
    certificate.signature = m_crypto_backend.sign_data(m_root_key_pair.private_key, data_buffer);

    return certificate;
}

CertificateValidity CertificateManager::check_certificate(const Certificate& certificate)
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
                return CertificateInvalidReason::BROKEN_TIME_PERIOD;
            }
            // check if certificate is premature or outdated
            if (get_time_in_seconds() < start_and_end.start_validity || get_time_in_seconds() > start_and_end.end_validity) {
                return CertificateInvalidReason::OFF_TIME_PERIOD;
            }
        }
    }

    // check if subject_name is empty
    if (0 != certificate.subject_info.subject_name.size()) {
        return CertificateInvalidReason::INVALID_NAME;
    }

    // check signer info
    if(get_type(certificate.signer_info) == SignerInfoType::Certificate_Digest_With_SHA256) {
        HashedId8 signer_hash = boost::get<HashedId8>(certificate.signer_info);
        if(signer_hash != m_root_certificate_hash) {
            return CertificateInvalidReason::INVALID_ROOT_HASH;
        }
    }

    // create ByteBuffer of Signature
    boost::optional<ByteBuffer> sig = extract_signature_buffer(certificate.signature);
    if (!sig) {
        return CertificateInvalidReason::MISSING_SIGNATURE;
    }

    // create buffer of certificate
    ByteBuffer cert = convert_for_signing(certificate);

    if (!m_crypto_backend.verify_data(m_root_key_pair.public_key, cert, sig.get())) {
        return CertificateInvalidReason::INVALID_SIGNATURE;
    }

    return CertificateValidity::valid();
}

boost::optional<BackendCryptoPP::PublicKey> CertificateManager::get_public_key_from_certificate(const Certificate& certificate)
{
    boost::optional<BackendCryptoPP::PublicKey> public_key;
    boost::optional<Uncompressed> public_key_coordinates = get_public_key(certificate);
    if (public_key_coordinates) {
        public_key = m_crypto_backend.public_key(*public_key_coordinates);
    }

    return public_key;
}

void CertificateManager::enable_deferred_signing(bool flag)
{
    m_sign_deferred = flag;
}

Time64 CertificateManager::get_time()
{
    return convert_time64(m_time_now);
}

Time32 CertificateManager::get_time_in_seconds()
{
    return convert_time32(m_time_now);
}

const BackendCryptoPP::KeyPair& CertificateManager::get_root_key_pair()
{
    static BackendCryptoPP::KeyPair root = m_crypto_backend.generate_key_pair();
    return root;
}

} // namespace security
} // namespace vanetza
