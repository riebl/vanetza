#pragma once
#include <vanetza/security/v3/authorization_ticket_pool.hpp>
#include <map>

namespace vanetza
{
namespace security
{
namespace v3
{

/**
 * \brief Authorization ticket pool keeping its tickets in memory
 */
class MemoryAuthorizationTicketPool : public AuthorizationTicketPool
{
public:
    bool add(const Credential& ticket) override;
    bool remove(const HashedId8& ticket) override;
    void visit(Visitor& visitor) const override;
    boost::optional<Credential> fetch(const HashedId8& ticket) const override;

private:
    std::map<HashedId8, Credential> m_tickets;
};

} // namespace v3
} // namespace security
} // namespace vanetza
