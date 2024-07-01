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
    SecuredMessage secured_message;
    secured_message->protocolVersion = 3;
    secured_message->content = static_cast<struct Ieee1609Dot2Content*>(calloc(1, sizeof(struct Ieee1609Dot2Content)));
    secured_message->content->present = Ieee1609Dot2Content_PR_signedData;
    secured_message->content->choice.signedData = static_cast<struct SignedData*>(calloc(1, sizeof(struct SignedData)));
    secured_message->content->choice.signedData->tbsData = static_cast<struct ToBeSignedData*>(calloc(1, sizeof(struct ToBeSignedData)));
    secured_message->content->choice.signedData->tbsData->payload = static_cast<struct SignedDataPayload*>(calloc(1, sizeof(struct SignedDataPayload)));
    secured_message->content->choice.signedData->tbsData->payload->data = static_cast<struct Ieee1609Dot2Data*>(calloc(1, sizeof(struct Ieee1609Dot2Data)));
    secured_message->content->choice.signedData->tbsData->payload->data->protocolVersion = 3;
    secured_message->content->choice.signedData->tbsData->payload->data->content = static_cast<struct Ieee1609Dot2Content*>(calloc(1, sizeof(struct Ieee1609Dot2Content)));
    secured_message->content->choice.signedData->tbsData->payload->data->content->present = Ieee1609Dot2Content_PR_unsecuredData;

    ByteBuffer payload;
    payload = convert_to_payload(request.plain_message);
    secured_message.set_payload(payload);

    m_policy.prepare_header(request, m_certificates, secured_message);

    ByteBuffer to_be_signed_data = secured_message.convert_for_signing();
    const auto& private_key = m_certificates.own_private_key();
    EcdsaSignature signature = m_backend.sign_data(private_key, to_be_signed_data);
    secured_message.set_signature(signature);

    SignConfirm confirm;
    confirm.secured_message = std::move(secured_message);
    return confirm;
}

DummySignService::DummySignService(const Runtime& runtime, const SignerInfo& signer) :
    m_runtime(runtime), m_signer_info(signer)
{
}

SignConfirm DummySignService::sign(SignRequest&& request)
{
    SecuredMessage secured_message;
    secured_message->protocolVersion = 3;
    secured_message->content = static_cast<struct Ieee1609Dot2Content*>(calloc(1, sizeof(struct Ieee1609Dot2Content)));
    secured_message->content->present = Ieee1609Dot2Content_PR_signedData;
    secured_message->content->choice.signedData = static_cast<struct SignedData*>(calloc(1, sizeof(struct SignedData)));
    secured_message->content->choice.signedData->tbsData = static_cast<struct ToBeSignedData*>(calloc(1, sizeof(struct ToBeSignedData)));
    secured_message->content->choice.signedData->tbsData->payload = static_cast<struct SignedDataPayload*>(calloc(1, sizeof(struct SignedDataPayload)));
    secured_message->content->choice.signedData->tbsData->payload->data = static_cast<struct Ieee1609Dot2Data*>(calloc(1, sizeof(struct Ieee1609Dot2Data)));
    secured_message->content->choice.signedData->tbsData->payload->data->protocolVersion = 3;
    secured_message->content->choice.signedData->tbsData->payload->data->content = static_cast<struct Ieee1609Dot2Content*>(calloc(1, sizeof(struct Ieee1609Dot2Content)));
    secured_message->content->choice.signedData->tbsData->payload->data->content->present = Ieee1609Dot2Content_PR_unsecuredData;

    ByteBuffer payload;
    payload = convert_to_payload(request.plain_message);
    secured_message.set_payload(payload);
    secured_message.set_dummy_signature();
    secured_message.set_its_aid(request.its_aid);
    secured_message.set_generation_time(vanetza::security::v2::convert_time64(m_runtime.now()));
    secured_message.set_signer_info(m_signer_info);
    
    SignConfirm confirm;
    confirm.secured_message = std::move(secured_message);
    return confirm;
}

} // namespace v3
} // namespace security
} // namespace vanetza
