#include <vanetza/common/its_aid.hpp>
#include <vanetza/common/runtime.hpp>
#include <vanetza/security/v2/basic_elements.hpp>
#include <vanetza/security/backend.hpp>
#include <vanetza/security/crypto_provider.hpp>
#include <vanetza/security/security_module.hpp>
#include <vanetza/security/v3/credential_provider.hpp>
#include <vanetza/security/v3/hash.hpp>
#include <vanetza/security/v3/sign_service.hpp>
#include <vanetza/security/v3/secured_message.hpp>

namespace vanetza
{
namespace security
{
namespace v3
{

StraightSignService::StraightSignService(CertificateProvider& provider, Backend& backend, SignHeaderPolicy& policy, CertificateValidator& validator) :
    m_certificates(provider), m_backend(backend), m_policy(policy), m_validator(validator)
{
}

SignConfirm StraightSignService::sign(SignRequest&& request)
{
    const auto& signing_cert = m_certificates.own_certificate();
    const auto hash_algo = specified_hash_algorithm(signing_cert.get_verification_key_type());

    SecuredMessage secured_message = SecuredMessage::with_signed_data();
    secured_message.set_hash_id(hash_algo);
    secured_message.set_payload(convert_to_payload(request.plain_message));
    m_policy.prepare_header(request, signing_cert, secured_message);

    if (m_validator.valid_for_signing(signing_cert, request.its_aid) != CertificateValidator::Verdict::Valid) {
        return SignConfirm::failure(SignConfirmError::No_Certificate);
    }

    ByteBuffer digest = calculate_message_hash(m_backend, hash_algo, secured_message.signing_payload(), signing_cert);
    Signature signature = m_backend.sign_digest(m_certificates.own_private_key(), digest);
    secured_message.set_signature(signature);
    return SignConfirm::success(std::move(secured_message));
}

SecurityModuleSignService::SecurityModuleSignService(SecurityModule& module, CryptoProvider& crypto,
    CredentialProvider& credentials, SignHeaderPolicy& policy, CertificateValidator& validator) :
    m_credentials(credentials), m_module(module), m_crypto(crypto), m_policy(policy), m_validator(validator)
{
}

SignConfirm SecurityModuleSignService::sign(SignRequest&& request)
{
    const Credential* credential = m_credentials.signing_credential(request.its_aid);
    if (!credential) {
        return SignConfirm::failure(SignConfirmError::No_Certificate);
    }
    const Certificate& signing_cert = credential->certificate;
    const auto hash_algo = specified_hash_algorithm(signing_cert.get_verification_key_type());
    if (hash_algo == HashAlgorithm::Unspecified) {
        // ticket is unusable for signing, e.g. the key type of an implicit certificate is unknown
        return SignConfirm::failure(SignConfirmError::No_Certificate);
    }

    SecuredMessage secured_message = SecuredMessage::with_signed_data();
    secured_message.set_hash_id(hash_algo);
    secured_message.set_payload(convert_to_payload(request.plain_message));
    m_policy.prepare_header(request, signing_cert, secured_message);

    if (m_validator.valid_for_signing(signing_cert, request.its_aid) != CertificateValidator::Verdict::Valid) {
        return SignConfirm::failure(SignConfirmError::No_Certificate);
    }

    vanetza::asn1::asn1c_error error;
    const ByteBuffer payload = secured_message.signing_payload(error);
    if (error) {
        return SignConfirm::failure(SignConfirmError::Encoding_Failure);
    }

    const ByteBuffer digest = calculate_message_hash(m_crypto, hash_algo, payload, signing_cert);
    if (digest.empty()) {
        // signer certificate without encodable canonical form
        return SignConfirm::failure(SignConfirmError::Encoding_Failure);
    }
    expected<Signature> signature = m_module.sign(digest, credential->key);
    if (!signature) {
        return SignConfirm::failure(SignConfirmError::Unspecified);
    }
    secured_message.set_signature(*signature);
    return SignConfirm::success(std::move(secured_message));
}

DummySignService::DummySignService(const Runtime& runtime) :
    m_runtime(runtime)
{
}

SignConfirm DummySignService::sign(SignRequest&& request)
{
    SecuredMessage secured_message = SecuredMessage::with_signed_data();
    ByteBuffer payload;
    payload = convert_to_payload(request.plain_message);
    secured_message.set_payload(payload);
    secured_message.set_dummy_signature();
    secured_message.set_its_aid(request.its_aid);
    secured_message.set_generation_time(vanetza::security::v2::convert_time64(m_runtime.now()));
    secured_message->content->choice.signedData->signer.present = Vanetza_Security_SignerIdentifier_PR_self;

    return SignConfirm::success(std::move(secured_message));
}

} // namespace v3
} // namespace security
} // namespace vanetza
