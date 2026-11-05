#pragma once
#include <vanetza/security/hashed_id.hpp>
#include <vanetza/security/v3/credential_provider.hpp>
#include <boost/optional/optional.hpp>
#include <random>
#include <unordered_set>
#include <vector>

namespace vanetza
{

// forward declaration
class Runtime;

namespace security
{
namespace v3
{

// forward declarations
class AuthorizationTicketPool;

/**
 * \brief Manages the station's pseudonyms, each being one authorization ticket of a pool
 *
 * Tickets valid now are selected randomly without replacement per round (C2C-CC PP Vehicle C-ITS Station, FMT_SMF.1).
 * Changes are announced in two phases (ETSI TS 102 723-8, 6.3.1).
 * The current pseudonym is a copy, thus pool modifications take effect with the next change.
 */
class IdentityManager : public CredentialProvider
{
public:
    /**
     * \brief Subscriber of the two-phase pseudonym change (ETSI TS 102 723-8, 6.3.1),
     *        e.g. a layer deriving its identifier from the pseudonym
     */
    class Subscriber
    {
    public:
        /**
         * Prepare change, e.g. stop sending with the current pseudonym
         * \param next HashedId8 of next pseudonym's ticket
         * \return false to veto the change
         */
        virtual bool prepare(const HashedId8& next) = 0;

        /**
         * Change identifiers to next pseudonym
         * \param next HashedId8 of next pseudonym's ticket
         */
        virtual void commit(const HashedId8& next) = 0;

        /**
         * Keep current pseudonym after a prepared change has been vetoed
         */
        virtual void abort() = 0;

        virtual ~Subscriber() = default;
    };

    /**
     * Start with a randomly selected pseudonym if the pool holds any ticket valid now
     * \param pool authorization tickets the pseudonyms are derived from, it has to outlive this manager
     * \param runtime runtime telling the tickets valid now, it has to outlive this manager
     */
    IdentityManager(AuthorizationTicketPool& pool, const Runtime& runtime);

    /**
     * Get current pseudonym, e.g. for a new subscriber deriving its initial identifier
     * \return ticket of current pseudonym or nullptr if none has been selected yet
     */
    const Credential* current_pseudonym() const;

    /**
     * Get current pseudonym if its ticket permits the application
     * \param aid ITS-AID of the message
     * \return current pseudonym or nullptr
     */
    const Credential* signing_credential(ItsAid aid) override;

    /**
     * Change to the next pseudonym (SN-IDCHANGE-TRIGGER)
     * \return true if changed, false if vetoed or no other ticket valid now is available
     */
    bool change_pseudonym();

    /**
     * Subscribe to pseudonym changes (SN-IDCHANGE-SUBSCRIBE)
     *
     * Unsubscribing takes effect immediately: an unsubscribed subscriber receives no further calls, not even for
     * an ongoing change. A subscriber added during a change takes part from the next change on.
     * \param subscriber has to stay alive until unsubscribed
     */
    void subscribe(Subscriber& subscriber);
    void unsubscribe(Subscriber& subscriber);

private:
    class CandidateCollector;

    struct Pseudonym
    {
        HashedId8 id; // HashedId8 of ticket's certificate
        Credential ticket;
    };

    boost::optional<HashedId8> select_next();
    bool is_subscribed(const Subscriber*) const;

    AuthorizationTicketPool& m_pool;
    const Runtime& m_runtime;
    boost::optional<Pseudonym> m_current;
    std::unordered_set<HashedId8> m_used; // tickets used in current round
    std::vector<Subscriber*> m_subscribers;
    std::random_device m_random;
};

} // namespace v3
} // namespace security
} // namespace vanetza
