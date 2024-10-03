#include <vanetza/security/v3/static_certificate_provider.hpp>

namespace vanetza
{
namespace security
{
namespace v3
{

StaticCertificateProvider::StaticCertificateProvider(const Certificate& authorization_ticket,
    const PrivateKey& authorization_ticket_key) :
    authorization_ticket(authorization_ticket),
    authorization_ticket_key(authorization_ticket_key)
{
}

const PrivateKey& StaticCertificateProvider::own_private_key()
{
    return authorization_ticket_key;
}

const Certificate& StaticCertificateProvider::own_certificate()
{
    return authorization_ticket;
}

} // namespace v3
} // namespace security
} // namespace vanetza
