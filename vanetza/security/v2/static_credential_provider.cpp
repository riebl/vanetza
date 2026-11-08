#include <vanetza/security/v2/static_credential_provider.hpp>

namespace vanetza
{
namespace security
{
namespace v2
{

StaticCredentialProvider::StaticCredentialProvider(const Certificate& authorization_ticket,
    const Certificate& authorization_authority, const KeyReference& ticket_key) :
    m_credential { authorization_ticket, authorization_authority, ticket_key }
{
}

const Credential* StaticCredentialProvider::signing_credential(ItsAid)
{
    return &m_credential;
}

} // namespace v2
} // namespace security
} // namespace vanetza
