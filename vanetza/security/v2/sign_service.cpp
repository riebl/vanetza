#include <vanetza/common/its_aid.hpp>
#include <vanetza/common/runtime.hpp>
#include <vanetza/security/backend.hpp>
#include <vanetza/security/crypto_provider.hpp>
#include <vanetza/security/security_module.hpp>
#include <vanetza/security/v2/certificate_provider.hpp>
#include <vanetza/security/v2/credential_provider.hpp>
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

SecurityModuleSignService::SecurityModuleSignService(SecurityModule& module, CryptoProvider& crypto,
    CredentialProvider& credentials, SignHeaderPolicy& policy) :
    m_module(module), m_crypto(crypto), m_credentials(credentials), m_policy(policy)
{
}

SignConfirm SecurityModuleSignService::sign(SignRequest&& request)
{
    const Credential* credential = m_credentials.signing_credential(request.its_aid);
    if (!credential) {
        return SignConfirm::failure(SignConfirmError::No_Certificate);
    }

    SecuredMessage secured_message;
    secured_message.payload.type = PayloadType::Signed;
    secured_message.payload.data = std::move(request.plain_message);
    secured_message.header_fields = m_policy.prepare_header(request, *credential);

    static const Signature placeholder = signature_placeholder();
    static const std::list<TrailerField> trailer_fields = { placeholder };

    const ByteBuffer data_buffer = convert_for_signing(secured_message, trailer_fields);
    const Sha256Hash digest = m_crypto.calculate_sha256_hash(data_buffer.data(), data_buffer.size());
    const expected<security::Signature> signature =
        m_module.sign(ByteBuffer(digest.octets.begin(), digest.octets.end()), credential->key);
    if (!signature || signature->type != KeyType::NistP256) {
        // v2 messages are signed by NIST P-256 keys only
        return SignConfirm::failure(SignConfirmError::Unspecified);
    }

    // r is the x-coordinate of R
    secured_message.trailer_fields.push_back(EcdsaSignature { X_Coordinate_Only { signature->r }, signature->s });
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
