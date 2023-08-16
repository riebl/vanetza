#ifndef DELEGATING_SECURITY_ENTITY_HPP_W1MFSVEN
#define DELEGATING_SECURITY_ENTITY_HPP_W1MFSVEN

#include <vanetza/security/security_entity.hpp>
#include <vanetza/security/sign_service.hpp>
#include <vanetza/security/verify_service.hpp>
#include <memory>

namespace vanetza
{
namespace security
{

/**
 * Implementation of SecurityEntity delegating to SignService and VerifyService
 */
class DelegatingSecurityEntity : public SecurityEntity
{
public:
    /**
     * \brief Create security entity from primitive services.
     *
     * A std::invalid_argument exception is thrown at construction
     * if any given service is not callable.
     *
     * \param sign SN-SIGN service
     * \param verify SN-VERIFY service
     */
    DelegatingSecurityEntity(std::unique_ptr<SignService> sign, std::unique_ptr<VerifyService> verify);

    EncapConfirm encapsulate_packet(EncapRequest&& encap_request) override;
    DecapConfirm decapsulate_packet(DecapRequest&& decap_request) override;

private:
    std::unique_ptr<SignService> m_sign_service;
    std::unique_ptr<VerifyService> m_verify_service;
};

} // namespace security
} // namespace vanetza

#endif /* DELEGATING_SECURITY_ENTITY_HPP_W1MFSVEN */
