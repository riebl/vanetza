#include <vanetza/security/security_entity.hpp>
#include <vanetza/security/backend_cryptopp.hpp>
#include <vanetza/security/certificate_manager.hpp>
#include <vanetza/security/its_aid.hpp>
#include <future>

namespace vanetza
{
namespace security
{

SecurityEntity::SecurityEntity(const Clock::time_point& time_now) :
    m_time_now(time_now), m_sign_deferred(false),
    m_certificate_manager(new CertificateManager(time_now)),
    m_crypto_backend(new BackendCryptoPP())
{
}

EncapConfirm SecurityEntity::encapsulate_packet(const EncapRequest& encap_request)
{
    return sign(encap_request);
}

DecapConfirm SecurityEntity::decapsulate_packet(const DecapRequest& decap_request)
{
    return verify(decap_request);
}

EncapConfirm SecurityEntity::sign(const EncapRequest& request)
{
    EncapConfirm encap_confirm;
    // set secured message data
    encap_confirm.sec_packet.payload.type = PayloadType::Signed;
    encap_confirm.sec_packet.payload.data = std::move(request.plaintext_payload);
    // set header field data
    encap_confirm.sec_packet.header_fields.push_back(convert_time64(m_time_now));
    encap_confirm.sec_packet.header_fields.push_back(itsAidCa);

    SignerInfo signer_info = m_certificate_manager->own_certificate();
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
    const auto& private_key = m_certificate_manager->own_private_key();
    if (m_sign_deferred) {
        auto future = std::async(std::launch::deferred, [=]() {
            ByteBuffer data = convert_for_signing(encap_confirm.sec_packet, trailer_field_size);
            return m_crypto_backend->sign_data(private_key, data);
        });
        EcdsaSignatureFuture signature(future.share(), signature_size);
        encap_confirm.sec_packet.trailer_fields.push_back(signature);
    } else {
        ByteBuffer data_buffer = convert_for_signing(encap_confirm.sec_packet, trailer_field_size);
        TrailerField trailer_field = m_crypto_backend->sign_data(private_key, data_buffer);
        assert(get_size(trailer_field) == trailer_field_size);
        encap_confirm.sec_packet.trailer_fields.push_back(trailer_field);
    }

    return encap_confirm;
}

DecapConfirm SecurityEntity::verify(const DecapRequest& decap_request)
{
    return m_certificate_manager->verify_message(decap_request);
}

void SecurityEntity::enable_deferred_signing(bool flag)
{
    m_sign_deferred = flag;
}

} // namespace security
} // namespace vanetza
