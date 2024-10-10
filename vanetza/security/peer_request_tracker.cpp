#include <vanetza/security/peer_request_tracker.hpp>
#include <cassert>

namespace vanetza
{
namespace security
{

PeerRequestTracker::PeerRequestTracker(std::size_t limit) : m_limit(limit)
{
}

void PeerRequestTracker::add_request(const HashedId3& id)
{
    if (!is_pending(id)) {
        // drop tail item when queue becomes full
        if (m_fifo.size() >= m_limit && !m_fifo.empty()) {
            m_lookup.erase(m_fifo.front());
            m_fifo.pop_front();
        }

        auto inserted = m_fifo.insert(m_fifo.end(), id);
        m_lookup.emplace(id, inserted);
    }

    assert(m_fifo.size() == m_lookup.size());
}

void PeerRequestTracker::discard_request(const HashedId3& id)
{
    auto found = m_lookup.find(id);
    if (found != m_lookup.end()) {
        m_fifo.erase(found->second);
        m_lookup.erase(found);
    }

    assert(m_fifo.size() == m_lookup.size());
}

bool PeerRequestTracker::is_pending(const HashedId3& id) const
{
    return m_lookup.find(id) != m_lookup.end();
}

boost::optional<HashedId3> PeerRequestTracker::next_one()
{
    boost::optional<HashedId3> next;
    if (!m_fifo.empty()) {
        next = m_fifo.front();
        m_fifo.pop_front();
        m_lookup.erase(*next);
    }

    assert(m_fifo.size() == m_lookup.size());
    return next;
}

std::list<HashedId3> PeerRequestTracker::next_n(std::size_t max)
{
    if (max >= m_fifo.size()) {
        return all();
    } else {
        std::list<HashedId3> next;
        auto from = m_fifo.begin();
        auto to = std::next(from, max);
        next.splice(next.begin(), m_fifo, from, to);

        for (const HashedId3& id : next) {
            m_lookup.erase(id);
        }

        assert(m_fifo.size() == m_lookup.size());
        return next;
    }
}

std::list<HashedId3> PeerRequestTracker::all()
{
    m_lookup.clear();
    std::list<HashedId3> all;
    all.splice(all.begin(), m_fifo, m_fifo.begin(), m_fifo.end());
    return all;
}

} // namespace security
} // namespace vanetza
