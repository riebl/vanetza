#include <vanetza/security/v3/memory_authorization_ticket_pool.hpp>

namespace vanetza
{
namespace security
{
namespace v3
{

bool MemoryAuthorizationTicketPool::add(const Credential& ticket)
{
    const boost::optional<HashedId8> id = ticket.certificate.calculate_digest();
    if (!id) {
        return false;
    }
    auto stored = m_tickets.emplace(*id, ticket);
    if (!stored.second) {
        // same HashedId8 means same certificate, thus only its key reference may differ
        stored.first->second.key = ticket.key;
    }
    return true;
}

bool MemoryAuthorizationTicketPool::remove(const HashedId8& ticket)
{
    return m_tickets.erase(ticket) > 0;
}

void MemoryAuthorizationTicketPool::visit(Visitor& visitor) const
{
    for (const auto& ticket : m_tickets) {
        visitor.visit(ticket.first, ticket.second);
    }
}

boost::optional<Credential> MemoryAuthorizationTicketPool::fetch(const HashedId8& ticket) const
{
    boost::optional<Credential> credential;
    auto found = m_tickets.find(ticket);
    if (found != m_tickets.end()) {
        credential = found->second;
    }
    return credential;
}

} // namespace v3
} // namespace security
} // namespace vanetza
