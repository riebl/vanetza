#include <vanetza/common/its_aid.hpp>
#include <vanetza/common/runtime.hpp>
#include <vanetza/security/backend.hpp>
#include <vanetza/security/certificate_provider.hpp>
#include <vanetza/security/sign_header_policy.hpp>
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
    const auto size = field_size(PublicKeyAlgorithm::ECDSA_NISTP256_With_SHA256);
    EcdsaSignature ecdsa;
    ecdsa.s.resize(size, 0x00);
    X_Coordinate_Only coordinate;
    coordinate.x.resize(size, 0x00);
    ecdsa.R = std::move(coordinate);
    return Signature { std::move(ecdsa) };
}

} // namespace


SignService straight_sign_service(CertificateProvider& certificate_provider, Backend& backend, SignHeaderPolicy& sign_header_policy)
{
    return [&](SignRequest&& request) -> SignConfirm {
        SignConfirm confirm;
        confirm.secured_message.payload.type = PayloadType::Signed;
        confirm.secured_message.payload.data = std::move(request.plain_message);
        confirm.secured_message.header_fields = sign_header_policy.prepare_header(request, certificate_provider);

        const auto& private_key = certificate_provider.own_private_key();
        static const Signature placeholder = signature_placeholder();
        static const std::list<TrailerField> trailer_fields = { placeholder };

        ByteBuffer data_buffer = convert_for_signing(confirm.secured_message, trailer_fields);
        TrailerField trailer_field = backend.sign_data(private_key, data_buffer);
        confirm.secured_message.trailer_fields.push_back(trailer_field);
        return confirm;
    };
}

SignService deferred_sign_service(CertificateProvider& certificate_provider, Backend& backend, SignHeaderPolicy& sign_header_policy)
{
    return [&](SignRequest&& request) -> SignConfirm {
        SignConfirm confirm;
        confirm.secured_message.payload.type = PayloadType::Signed;
        confirm.secured_message.payload.data = std::move(request.plain_message);
        confirm.secured_message.header_fields = sign_header_policy.prepare_header(request, certificate_provider);

        const auto& private_key = certificate_provider.own_private_key();
        static const Signature placeholder = signature_placeholder();
        static const size_t signature_size = get_size(placeholder);
        static const std::list<TrailerField> trailer_fields = { placeholder };

        const SecuredMessage& secured_message = confirm.secured_message;
        auto future = std::async(std::launch::deferred, [&backend, secured_message, private_key]() {
            ByteBuffer data = convert_for_signing(secured_message, trailer_fields);
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
