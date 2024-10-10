#ifndef A5037FF9_14E0_4DA9_8027_6C0692B1462B
#define A5037FF9_14E0_4DA9_8027_6C0692B1462B

#include <vanetza/security/hashed_id.hpp>
#include <boost/optional/optional.hpp>
#include <list>
#include <unordered_map>

namespace vanetza
{
namespace security
{

class PeerRequestTracker
{
public:
    explicit PeerRequestTracker(std::size_t limit = 16);

    /**
     * Add a certificate request to the tracker.
     * 
     * \param id hash of requested certificate
     */
    void add_request(const HashedId3&);

    /**
     * Discard a pending certificate request.
     * 
     * \param id hash of certificate
     */
    void discard_request(const HashedId3&);

    /**
     * Check if a certificate request is pending.
     * 
     * \param id hash of certificate
     * \return true if request of this certificate is pending
     */
    bool is_pending(const HashedId3&) const;

    /**
     * Determine which request shall be handled next and remove it from the queue.
     * 
     * \return hash of requested certificate if any
     */
    boost::optional<HashedId3> next_one();

    /**
     * Retrieve next n pending requests from tracker.
     * 
     * \return list of up to n certificate hashes
     */
    std::list<HashedId3> next_n(std::size_t max);

    /**
     * Retrieve all pending requests from tracker.
     * 
     * \return list of all pending certificate hashes
     */
    std::list<HashedId3> all();

private:
    using FifoQueue = std::list<HashedId3>;
    using LookupMap = std::unordered_map<HashedId3, FifoQueue::iterator>;

    std::size_t m_limit;
    FifoQueue m_fifo;
    LookupMap m_lookup;
};

} // namespace security
} // namespace vanetza

#endif /* A5037FF9_14E0_4DA9_8027_6C0692B1462B */
