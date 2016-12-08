#ifndef CBF_COUNTER_HPP_QTMUOGJS
#define CBF_COUNTER_HPP_QTMUOGJS

#include <vanetza/common/clock.hpp>
#include <vanetza/geonet/cbf_packet_identifier.hpp>
#include <vanetza/geonet/soft_state_map.hpp>
#include <cstddef>
#include <unordered_map>

namespace vanetza
{

// forward declaration
class Runtime;

namespace geonet
{

/**
 * Interface for duplicate packet counters.
 * This is used by the Contention Based Forwarding (CBF) packet buffer.
 */
class CbfCounter
{
public:
    using id_type = CbfPacketIdentifier;
    using counter_type = std::size_t;

    /**
     * Packet has been added to buffer
     * \param id packet identifier
     */
    virtual void add(const id_type& id) = 0;

    /**
     * Packet has been removed from buffer.
     * \param id packet identifier
     */
    virtual void remove(const id_type& id) = 0;

    /**
     * Increment packet counter by one
     * \param id packet identifier
     */
    virtual void increment(const id_type& id) = 0;

    /**
     * Retrieve counter value
     * \param id packet identifier
     */
    virtual counter_type counter(const id_type& id) const = 0;

    virtual ~CbfCounter() = default;
};


/**
 * Immortal CBF counters, i.e. they never expire.
 * \note Be aware, memory consumption is constantly growing of this implemenation!
 */
class CbfCounterImmortal : public virtual CbfCounter
{
public:
    void add(const id_type&) override;
    void remove(const id_type&) override {}
    void increment(const id_type&) override;
    counter_type counter(const id_type&) const override;

protected:
    std::unordered_map<id_type, counter_type> m_counters;
};

/**
 * Remembers only counter values for packets currently contending, i.e. stored in CBF buffer.
 * \note This is the ADVANCED routing behaviour of EN 302 636-4-1 v1.2.1
 */
class CbfCounterContending : public virtual CbfCounter, private CbfCounterImmortal
{
public:
    void add(const id_type&) override;
    void remove(const id_type&) override;
};

/**
 * Fading CBF counters
 *
 * Counters are removed from the internal table only after expiry, i.e. they are soft-state.
 * This fixes some serious GN flooding due to ADVANCED routing, see CbfCounterContending.
 */
class CbfCounterFading : public virtual CbfCounter
{
public:
    /*
     * Initialize fading counters
     * \param rt runtime used for soft-state behaviour
     * \param lifetime newly added counters are initialized with this lifetime
     */
    CbfCounterFading(Runtime&, Clock::duration lifetime);

    void add(const id_type&) override;
    void remove(const id_type&) override {}
    void increment(const id_type&) override;
    counter_type counter(const id_type&) const override;

private:
    SoftStateMap<id_type, counter_type> m_counters;
};

} // namespace geonet
} // namespace vanetza

#endif /* CBF_COUNTER_HPP_QTMUOGJS */

