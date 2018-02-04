#include <vanetza/security/security_entity.hpp>
#include <stdexcept>

namespace vanetza
{
namespace security
{

SecurityEntity::SecurityEntity(SignService sign, VerifyService verify) :
    m_sign_service(std::move(sign)),
    m_verify_service(std::move(verify))
{
    if (!m_sign_service) {
        throw std::invalid_argument("SN-SIGN service is not callable");
    } else if (!m_verify_service) {
        throw std::invalid_argument("SN-VERIFY service is not callable");
    }
}

SecurityEntity::~SecurityEntity()
{
    // only defined here so unique_ptr members can be used with incomplete types
}

EncapConfirm SecurityEntity::encapsulate_packet(EncapRequest&& encap_request)
{
    SignRequest sign_request;
    sign_request.plain_message = std::move(encap_request.plaintext_payload);
    // TODO: switch from profile to ITS-AID in EncapRequest
    switch (encap_request.security_profile.value_or(Profile::Generic)) {
        case Profile::CAM:
            sign_request.its_aid = itsAidCa;
            break;
        case Profile::DENM:
            sign_request.its_aid = itsAidDen;
            break;
        default:
            break;
    }

    SignConfirm sign_confirm = m_sign_service(std::move(sign_request));
    EncapConfirm encap_confirm;
    encap_confirm.sec_packet = std::move(sign_confirm.secured_message);
    return encap_confirm;
}

DecapConfirm SecurityEntity::decapsulate_packet(DecapRequest&& decap_request)
{
    DecapConfirm decap_confirm = m_verify_service(decap_request);
    decap_confirm.plaintext_payload = std::move(decap_request.sec_packet.payload.data);
    return decap_confirm;
}

} // namespace security
} // namespace vanetza
