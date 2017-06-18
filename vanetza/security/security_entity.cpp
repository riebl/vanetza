#include <vanetza/security/security_entity.hpp>
#include <vanetza/security/backend.hpp>
#include <vanetza/security/certificate_manager.hpp>
#include <vanetza/security/its_aid.hpp>
#include <future>
#include <stdexcept>
#include <string>

namespace vanetza
{
namespace security
{

SecurityEntity::SecurityEntity(Runtime& rt, Backend& backend, CertificateManager& manager) :
    m_runtime(rt),
    m_certificate_manager(manager),
    m_crypto_backend(backend),
    m_verify_service(straight_verify_service(rt, manager, backend))
{
    enable_deferred_signing(false);
}

SecurityEntity::~SecurityEntity()
{
    // only defined here so unique_ptr members can be used with incomplete types
}

EncapConfirm SecurityEntity::encapsulate_packet(const EncapRequest& encap_request)
{
    SignRequest sign_request;
    sign_request.plain_message = encap_request.plaintext_payload;
    sign_request.its_aid = itsAidCa; // TODO add ITS-AID to EncapRequest

    SignConfirm sign_confirm = m_sign_service(std::move(sign_request));
    EncapConfirm encap_confirm;
    encap_confirm.sec_packet = std::move(sign_confirm.secured_message);
    return encap_confirm;
}

DecapConfirm SecurityEntity::decapsulate_packet(const DecapRequest& decap_request)
{
    VerifyConfirm verify_confirm = m_verify_service(VerifyRequest { decap_request.sec_packet });
    DecapConfirm decap_confirm;
    decap_confirm.plaintext_payload = decap_request.sec_packet.payload.data;
    decap_confirm.report = static_cast<DecapReport>(verify_confirm.report);
    decap_confirm.certificate_validity = verify_confirm.certificate_validity;
    return decap_confirm;
}

void SecurityEntity::enable_deferred_signing(bool flag)
{
    if (flag) {
        m_sign_service = deferred_sign_service(m_runtime, m_certificate_manager, m_crypto_backend);
    } else {
        m_sign_service = straight_sign_service(m_runtime, m_certificate_manager, m_crypto_backend);
    }
    assert(m_sign_service);
}

} // namespace security
} // namespace vanetza
