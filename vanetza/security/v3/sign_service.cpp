#include <vanetza/common/its_aid.hpp>
#include <vanetza/common/runtime.hpp>
#include <vanetza/security/v2/basic_elements.hpp>
#include <vanetza/security/backend.hpp>
#include <vanetza/security/v3/sign_service.hpp>
#include <vanetza/security/v3/secured_message.hpp>
#include <iostream>
#include <future>

namespace vanetza
{
namespace security
{
namespace v3
{

void printByteBuffer(const ByteBuffer& buffer) {
    for (size_t i = 0; i < buffer.size(); ++i) {
        // Print each byte in hexadecimal format
        std::cout << std::hex << static_cast<int>(buffer[i]) << ' ';
    }
    std::cout << std::dec << std::endl; // Reset stream to decimal format
}

StraightSignService::StraightSignService(CertificateProvider& provider, Backend& backend, SignHeaderPolicy& policy) :
    m_certificates(provider), m_backend(backend), m_policy(policy)
{
}

SignConfirm StraightSignService::sign(SignRequest&& request)
{
    const auto& signing_cert = m_certificates.own_certificate();
    const auto hash_algo = specified_hash_algorithm(signing_cert.get_verification_key_type());

    SecuredMessage secured_message = SecuredMessage::with_signed_data();
    secured_message.set_hash_id(hash_algo);
    secured_message.set_payload(convert_to_payload(request.plain_message));
    m_policy.prepare_header(request, secured_message);

    ByteBuffer digest = calculate_message_hash(m_backend, hash_algo, secured_message.signing_payload(), signing_cert);
    Signature signature = m_backend.sign_digest(m_certificates.own_private_key(), digest);
    secured_message.set_signature(signature);

    SignConfirm confirm;
    confirm.secured_message = std::move(secured_message);
    return confirm;
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

    SignConfirm confirm;
    confirm.secured_message = std::move(secured_message);
    return confirm;
}

ByteBuffer calculate_message_hash(Backend& backend, HashAlgorithm hash_algo, const ByteBuffer& payload, const Certificate& signing_cert)
{
    ByteBuffer data_hash = backend.calculate_hash(hash_algo, payload);
    ByteBuffer cert_hash = backend.calculate_hash(hash_algo, signing_cert.encode());
    ByteBuffer concat_hash;
    concat_hash.reserve(data_hash.size() + cert_hash.size());
    concat_hash.insert(concat_hash.end(), data_hash.begin(), data_hash.end());
    concat_hash.insert(concat_hash.end(), cert_hash.begin(), cert_hash.end());
    return backend.calculate_hash(hash_algo, concat_hash);
}

HashAlgorithm specified_hash_algorithm(KeyType key_type)
{
    switch (key_type) {
        case KeyType::NistP256:
        case KeyType::BrainpoolP256r1:
            return HashAlgorithm::SHA256;
        case KeyType::BrainpoolP384r1:
            return HashAlgorithm::SHA384;
        default:
            return HashAlgorithm::Unspecified;
    }
}

} // namespace v3
} // namespace security
} // namespace vanetza
