#include <vanetza/common/runtime.hpp>
#include <vanetza/security/v3/authorization_ticket_pool.hpp>
#include <vanetza/security/v3/identity_manager.hpp>
#include <algorithm>

namespace vanetza
{
namespace security
{
namespace v3
{

namespace
{

// picks one of the offered tickets with equal probability without storing them (reservoir sampling)
class ReservoirSampler
{
public:
    explicit ReservoirSampler(std::mt19937::result_type seed) : m_engine(seed)
    {
    }

    void offer(const HashedId8& ticket)
    {
        ++m_offered;
        // n-th offered ticket replaces the previous selection with probability 1/n
        if (std::uniform_int_distribution<std::size_t>(1, m_offered)(m_engine) == 1) {
            m_selected = ticket;
        }
    }

    const boost::optional<HashedId8>& selected() const { return m_selected; }

private:
    std::mt19937 m_engine;
    std::size_t m_offered = 0;
    boost::optional<HashedId8> m_selected;
};

} // namespace

// offers the tickets eligible as next pseudonym to a sampler,
// i.e. those valid now and not used in the current round except the current pseudonym's ticket
class IdentityManager::CandidateCollector : public AuthorizationTicketPool::Visitor
{
public:
    CandidateCollector(const IdentityManager& manager, ReservoirSampler& sampler) :
        m_manager(manager), m_now(manager.m_runtime.now()), m_sampler(sampler)
    {
    }

    void visit(const HashedId8& id, const Credential& ticket) override
    {
        const bool current = m_manager.m_current && m_manager.m_current->id == id;
        const bool used = m_manager.m_used.count(id) > 0;
        if (!current && !used && ticket.certificate.valid_at_timepoint(m_now)) {
            m_sampler.offer(id);
        }
    }

private:
    const IdentityManager& m_manager;
    Clock::time_point m_now;
    ReservoirSampler& m_sampler;
};

IdentityManager::IdentityManager(AuthorizationTicketPool& pool, const Runtime& runtime) :
    m_pool(pool), m_runtime(runtime)
{
    // nothing to change from at start, thus no two-phase announcement
    const boost::optional<HashedId8> initial_id = select_next();
    if (initial_id) {
        boost::optional<Credential> initial = m_pool.fetch(*initial_id);
        if (initial) {
            m_current = Pseudonym { *initial_id, std::move(*initial) };
            m_used.insert(*initial_id);
        }
    }
}

const Credential* IdentityManager::current_pseudonym() const
{
    return m_current ? &m_current->ticket : nullptr;
}

const Credential* IdentityManager::signing_credential(ItsAid aid)
{
    return m_current && m_current->ticket.certificate.valid_for_application(aid) ? &m_current->ticket : nullptr;
}

boost::optional<HashedId8> IdentityManager::select_next()
{
    auto sample = [this]() {
        ReservoirSampler sampler { m_random() };
        CandidateCollector collector { *this, sampler };
        m_pool.visit(collector);
        return sampler.selected();
    };

    boost::optional<HashedId8> selected = sample();
    if (!selected && !m_used.empty()) {
        // all tickets valid now have been used in this round, start the next round
        m_used.clear();
        selected = sample();
    }
    return selected;
}

bool IdentityManager::change_pseudonym()
{
    const boost::optional<HashedId8> next_id = select_next();
    if (!next_id) {
        return false;
    }
    boost::optional<Credential> next = m_pool.fetch(*next_id);
    if (!next) {
        return false;
    }

    // subscribers taking part in this change, those unsubscribing meanwhile are skipped
    const std::vector<Subscriber*> subscribers = m_subscribers;
    for (std::size_t i = 0; i < subscribers.size(); ++i) {
        if (is_subscribed(subscribers[i]) && !subscribers[i]->prepare(*next_id)) {
            // every subscriber prepared so far, including the vetoing one, keeps the current pseudonym
            for (std::size_t j = 0; j <= i; ++j) {
                if (is_subscribed(subscribers[j])) {
                    subscribers[j]->abort();
                }
            }
            return false;
        }
    }

    m_current = Pseudonym { *next_id, std::move(*next) };
    m_used.insert(*next_id);
    for (Subscriber* subscriber : subscribers) {
        if (is_subscribed(subscriber)) {
            subscriber->commit(*next_id);
        }
    }
    return true;
}

bool IdentityManager::is_subscribed(const Subscriber* subscriber) const
{
    return std::find(m_subscribers.begin(), m_subscribers.end(), subscriber) != m_subscribers.end();
}

void IdentityManager::subscribe(Subscriber& subscriber)
{
    if (!is_subscribed(&subscriber)) {
        m_subscribers.push_back(&subscriber);
    }
}

void IdentityManager::unsubscribe(Subscriber& subscriber)
{
    m_subscribers.erase(std::remove(m_subscribers.begin(), m_subscribers.end(), &subscriber), m_subscribers.end());
}

} // namespace v3
} // namespace security
} // namespace vanetza
