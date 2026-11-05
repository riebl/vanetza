#pragma once
#include <vanetza/security/v3/credential_provider.hpp>

namespace vanetza
{
namespace security
{
namespace v3
{

/**
 * \brief Credential provider with a static authorization ticket and its key reference
 */
class StaticCredentialProvider : public CredentialProvider
{
public:
    /**
     * Create credential provider
     * \param authorization_ticket own certificate
     * \param ticket_key reference to private key of given authorization ticket
     */
    StaticCredentialProvider(const Certificate& authorization_ticket, const KeyReference& ticket_key);

    const Credential* signing_credential(ItsAid aid) override;

private:
    Credential m_credential;
};

} // namespace v3
} // namespace security
} // namespace vanetza
