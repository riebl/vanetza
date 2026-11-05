#include <vanetza/security/v3/static_credential_provider.hpp>

namespace vanetza
{
namespace security
{
namespace v3
{

StaticCredentialProvider::StaticCredentialProvider(const Certificate& authorization_ticket,
    const KeyReference& ticket_key) :
    m_credential { authorization_ticket, ticket_key }
{
}

const Credential* StaticCredentialProvider::signing_credential(ItsAid aid)
{
    return m_credential.certificate.valid_for_application(aid) ? &m_credential : nullptr;
}

} // namespace v3
} // namespace security
} // namespace vanetza
