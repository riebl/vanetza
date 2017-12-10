#include <vanetza/common/runtime.hpp>
#include <vanetza/security/backend.hpp>
#include <vanetza/security/certificate_provider.hpp>
#include <vanetza/security/sign_service.hpp>
#include <cassert>
#include <future>

namespace vanetza
{
namespace security
{
namespace
{

/**
 * \brief signature used as placeholder until final signature is calculated
 * \return placeholder containing dummy data
 */
Signature signature_placeholder()
{
    const auto size = field_size(PublicKeyAlgorithm::Ecdsa_Nistp256_With_Sha256);
    EcdsaSignature ecdsa;
    ecdsa.s.resize(size, 0x00);
    X_Coordinate_Only coordinate;
    coordinate.x.resize(size, 0x00);
    ecdsa.R = std::move(coordinate);
    return Signature { std::move(ecdsa) };
}

} // namespace


SignPreparer::SignPreparer(const Clock::time_point& time_now) : m_time_next_certificate(time_now) {}

SignConfirm SignPreparer::prepare_sign_confirm(SignRequest& request, const Certificate& certificate, Clock::time_point now)
{
    SignConfirm confirm;
    confirm.secured_message.payload.type = PayloadType::Signed;
    confirm.secured_message.payload.data = std::move(request.plain_message);
    confirm.secured_message.header_fields.push_back(convert_time64(now));
    confirm.secured_message.header_fields.push_back(request.its_aid);

    // See security profiles in section 7 of TS 103 097 v1.2.1
    if (request.its_aid == itsAidCa) {
        if (now < m_time_next_certificate) {
            confirm.secured_message.header_fields.push_back(SignerInfo { calculate_hash(certificate) });
        } else {
            confirm.secured_message.header_fields.push_back(SignerInfo { certificate });
            m_time_next_certificate = now + std::chrono::seconds(1);
        }
    } else if (request.its_aid == itsAidDen) {
        // TODO: Add generation_location
        confirm.secured_message.header_fields.push_back(SignerInfo { certificate });
    } else {
        // TODO: Add generation_location
        confirm.secured_message.header_fields.push_back(SignerInfo { certificate });
    }

    return confirm;
}

SignService straight_sign_service(Runtime& rt, CertificateProvider& certificates, Backend& backend, SignPreparer& sign_preparer)
{
    return [&](SignRequest&& request) -> SignConfirm {
        SignConfirm confirm = sign_preparer.prepare_sign_confirm(request, certificates.own_certificate(), rt.now());
        const auto& private_key = certificates.own_private_key();
        static const Signature placeholder = signature_placeholder();
        static const size_t trailer_size = get_size(TrailerField { placeholder });

        ByteBuffer data_buffer = convert_for_signing(confirm.secured_message, trailer_size);
        TrailerField trailer_field = backend.sign_data(private_key, data_buffer);
        assert(get_size(trailer_field) == trailer_size);
        confirm.secured_message.trailer_fields.push_back(trailer_field);
        return confirm;
    };
}

SignService deferred_sign_service(Runtime& rt, CertificateProvider& certificates, Backend& backend, SignPreparer& sign_preparer)
{
    return [&](SignRequest&& request) -> SignConfirm {
        SignConfirm confirm = sign_preparer.prepare_sign_confirm(request, certificates.own_certificate(), rt.now());
        const auto& private_key = certificates.own_private_key();
        static const Signature placeholder = signature_placeholder();
        static const size_t signature_size = get_size(placeholder);
        static const size_t trailer_size = get_size(TrailerField { placeholder });

        const SecuredMessage& secured_message = confirm.secured_message;
        auto future = std::async(std::launch::deferred, [&backend, secured_message, private_key]() {
            ByteBuffer data = convert_for_signing(secured_message, trailer_size);
            return backend.sign_data(private_key, data);
        });
        EcdsaSignatureFuture signature(future.share(), signature_size);
        confirm.secured_message.trailer_fields.push_back(signature);
        return confirm;
    };
}

SignService dummy_sign_service(const Runtime& rt, const SignerInfo& signer_info)
{
    return [&rt, signer_info](SignRequest&& request) -> SignConfirm {
        static const Signature null_signature = signature_placeholder();
        SignConfirm confirm;
        confirm.secured_message.payload.type = PayloadType::Signed;
        confirm.secured_message.payload.data = std::move(request.plain_message);
        confirm.secured_message.header_fields.push_back(convert_time64(rt.now()));
        confirm.secured_message.header_fields.push_back(request.its_aid);
        confirm.secured_message.header_fields.push_back(signer_info);
        confirm.secured_message.trailer_fields.push_back(null_signature);
        return confirm;
    };
}

} // namespace security
} // namespace vanetza
