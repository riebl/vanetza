#include <vanetza/common/its_aid.hpp>
#include <vanetza/common/runtime.hpp>
#include <vanetza/security/backend.hpp>
#include <vanetza/security/v2/certificate_provider.hpp>
#include <vanetza/security/v2/sign_header_policy.hpp>
#include <vanetza/security/v2/sign_service.hpp>
#include <vanetza/security/v2/signature.hpp>
#include <future>

namespace vanetza
{
namespace security
{
namespace v2
{

namespace
{

/**
 * \brief signature used as placeholder until final signature is calculated
 * \return placeholder containing dummy data
 */
EcdsaSignature signature_placeholder()
{
    const auto size = field_size(PublicKeyAlgorithm::ECDSA_NISTP256_With_SHA256);
    EcdsaSignature ecdsa;
    ecdsa.s.resize(size, 0x00);
    X_Coordinate_Only coordinate;
    coordinate.x.resize(size, 0x00);
    ecdsa.R = std::move(coordinate);
    return ecdsa;
}

} // namespace

StraightSignService::StraightSignService(CertificateProvider& provider, Backend& backend, SignHeaderPolicy& policy) :
    m_certificates(provider), m_backend(backend), m_policy(policy)
{
}

SignConfirm StraightSignService::sign(SignRequest&& request)
{
    SecuredMessage secured_message;
    secured_message.payload.type = PayloadType::Signed;
    secured_message.payload.data = std::move(request.plain_message);
    secured_message.header_fields = m_policy.prepare_header(request, m_certificates);

    const auto& private_key = m_certificates.own_private_key();
    static const Signature placeholder = signature_placeholder();
    static const std::list<TrailerField> trailer_fields = { placeholder };

    ByteBuffer data_buffer = convert_for_signing(secured_message, trailer_fields);
    TrailerField trailer_field = m_backend.sign_data(private_key, data_buffer);
    secured_message.trailer_fields.push_back(trailer_field);

    return SignConfirm::success(std::move(secured_message));
}

DeferredSignService::DeferredSignService(CertificateProvider& provider, Backend& backend, SignHeaderPolicy& policy) :
    m_certificates(provider), m_backend(backend), m_policy(policy)
{
}

SignConfirm DeferredSignService::sign(SignRequest&& request)
{
    SecuredMessage secured_message;
    secured_message.payload.type = PayloadType::Signed;
    secured_message.payload.data = std::move(request.plain_message);
    secured_message.header_fields = m_policy.prepare_header(request, m_certificates);

    const auto& private_key = m_certificates.own_private_key();
    static const EcdsaSignature placeholder = signature_placeholder();
    static const std::list<TrailerField> trailer_fields = { Signature { placeholder } };

    auto future = std::async(std::launch::deferred, [this, secured_message, private_key]() {
        ByteBuffer data = convert_for_signing(secured_message, trailer_fields);
        return m_backend.sign_data(private_key, data);
    });
    EcdsaSignatureFuture signature(future.share(), placeholder);
    secured_message.trailer_fields.push_back(Signature { std::move(signature) });

    return SignConfirm::success(std::move(secured_message));
}

DummySignService::DummySignService(const Runtime& runtime, const SignerInfo& signer) :
    m_runtime(runtime), m_signer_info(signer)
{
}

SignConfirm DummySignService::sign(SignRequest&& request)
{
    static const Signature null_signature { signature_placeholder() };

    SecuredMessage secured_message;
    secured_message.payload.type = PayloadType::Signed;
    secured_message.payload.data = std::move(request.plain_message);
    secured_message.header_fields.push_back(convert_time64(m_runtime.now()));
    secured_message.header_fields.push_back(request.its_aid);
    secured_message.header_fields.push_back(m_signer_info);
    secured_message.trailer_fields.push_back(null_signature);

    return SignConfirm::success(std::move(secured_message));
}

} // namespace v2
} // namespace security
} // namespace vanetza
