#pragma once
#include <vanetza/security/v2/credential_provider.hpp>

namespace vanetza
{
namespace security
{
namespace v2
{

/**
 * \brief Credential provider with a static authorization ticket, its issuer and key reference
 */
class StaticCredentialProvider : public CredentialProvider
{
public:
    /**
     * Create credential provider
     * \param authorization_ticket own certificate
     * \param authorization_authority issuer of authorization ticket
     * \param ticket_key reference to private key of given authorization ticket
     */
    StaticCredentialProvider(const Certificate& authorization_ticket, const Certificate& authorization_authority,
        const KeyReference& ticket_key);

    /**
     * \return the static credential for any aid
     */
    const Credential* signing_credential(ItsAid aid) override;

private:
    Credential m_credential;
};

} // namespace v2
} // namespace security
} // namespace vanetza
