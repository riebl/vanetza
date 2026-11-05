#pragma once
#include <vanetza/security/hashed_id.hpp>
#include <vanetza/security/v3/credential_provider.hpp>
#include <boost/optional/optional.hpp>

namespace vanetza
{
namespace security
{
namespace v3
{

/**
 * \brief Storage of authorization tickets along with their key references
 *
 * Tickets are identified by their certificate's HashedId8. The station derives its pseudonyms from these tickets.
 */
class AuthorizationTicketPool
{
public:
    class Visitor
    {
    public:
        /**
         * Visit a stored ticket
         * \param id HashedId8 of ticket's certificate
         * \param ticket ticket with its key reference
         */
        virtual void visit(const HashedId8& id, const Credential& ticket) = 0;

        virtual ~Visitor() = default;
    };

    /**
     * Add a ticket, replacing the key reference of an already stored ticket
     * \param ticket ticket with its key reference
     * \return false if ticket's certificate has no HashedId8, i.e. cannot be identified
     */
    virtual bool add(const Credential& ticket) = 0;

    /**
     * Remove a ticket
     * \param ticket HashedId8 of ticket's certificate
     * \return true if a ticket has been removed
     */
    virtual bool remove(const HashedId8& ticket) = 0;

    /**
     * Visit all stored tickets
     * \param visitor called once per ticket, must not modify this pool
     */
    virtual void visit(Visitor& visitor) const = 0;

    /**
     * Fetch a ticket
     * \param ticket HashedId8 of ticket's certificate
     * \return ticket with its key reference or none if not stored
     */
    virtual boost::optional<Credential> fetch(const HashedId8& ticket) const = 0;

    virtual ~AuthorizationTicketPool() = default;
};

} // namespace v3
} // namespace security
} // namespace vanetza
