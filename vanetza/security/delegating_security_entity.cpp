#include <vanetza/common/its_aid.hpp>
#include <vanetza/security/delegating_security_entity.hpp>
#include <stdexcept>

namespace vanetza
{
namespace security
{

DelegatingSecurityEntity::DelegatingSecurityEntity(std::unique_ptr<SignService> sign, std::unique_ptr<VerifyService> verify) :
    m_sign_service(std::move(sign)),
    m_verify_service(std::move(verify))
{
    if (!m_sign_service) {
        throw std::invalid_argument("SN-SIGN service is not callable");
    } else if (!m_verify_service) {
        throw std::invalid_argument("SN-VERIFY service is not callable");
    }
}

EncapConfirm DelegatingSecurityEntity::encapsulate_packet(EncapRequest&& encap_request)
{
    return dispatch(std::move(encap_request), m_sign_service.get());
}

DecapConfirm DelegatingSecurityEntity::decapsulate_packet(DecapRequest&& decap_request)
{
    DecapConfirm decap_confirm;

    VerifyConfirm verify_confirm = m_verify_service->verify(VerifyRequest { decap_request.sec_packet });
    decap_confirm.plaintext_payload = get_payload_copy(decap_request.sec_packet);
    decap_confirm.report = static_cast<DecapReport>(verify_confirm.report);
    decap_confirm.certificate_validity = verify_confirm.certificate_validity;
    decap_confirm.its_aid = verify_confirm.its_aid;
    decap_confirm.permissions = verify_confirm.permissions;
    
    return decap_confirm;
}

} // namespace security
} // namespace vanetza
