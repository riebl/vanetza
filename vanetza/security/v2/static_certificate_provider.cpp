#include <vanetza/security/v2/static_certificate_provider.hpp>

namespace vanetza
{
namespace security
{
namespace v2
{

StaticCertificateProvider::StaticCertificateProvider(const Certificate& authorization_ticket,
        const ecdsa256::PrivateKey& authorization_ticket_key) :
    StaticCertificateProvider(authorization_ticket, authorization_ticket_key, std::list<Certificate> {})
{
}

StaticCertificateProvider::StaticCertificateProvider(const Certificate& authorization_ticket,
        const ecdsa256::PrivateKey& authorization_ticket_key, const std::list<Certificate>& chain) :
    authorization_ticket(authorization_ticket), authorization_ticket_key(authorization_ticket_key), chain(chain)
{
}

const ecdsa256::PrivateKey& StaticCertificateProvider::own_private_key()
{
    return authorization_ticket_key;
}

std::list<Certificate> StaticCertificateProvider::own_chain()
{
    return chain;
}

const Certificate& StaticCertificateProvider::own_certificate()
{
    return authorization_ticket;
}

} // namespace v2
} // namespace security
} // namespace vanetza
