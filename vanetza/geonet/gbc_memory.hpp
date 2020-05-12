#ifndef GBC_MEMORY_HPP_032N8PRJ
#define GBC_MEMORY_HPP_032N8PRJ

#include <vanetza/geonet/cbf_packet_identifier.hpp>
#include <boost/multi_index_container.hpp>
#include <boost/multi_index/hashed_index.hpp>
#include <boost/multi_index/sequenced_index.hpp>

namespace vanetza
{
namespace geonet
{

/**
 * GbcMemory remembers previously seens GBC packets.
 *
 * GBC packets are identified by their (GN addr, sequence number) tuple.
 * The size of GbcMemory is bounded, i.e. it will forget old packets in favour of recent ones.
 */
class GbcMemory
{
public:
    using PacketIdentifier = CbfPacketIdentifier;

    /**
     * Forget a packet if memory exceeds upper limit of stored identifiers
     * \param num upper limit of remembered packets
     */
    void capacity(std::size_t num);

    /**
     * Number of currently known packets
     * \return number of packets
     */
    std::size_t size() const;

    /**
     * Remember a particular packet
     * \param id packet identifier
     * \return true if packet is already known
     */
    bool remember(const PacketIdentifier& id);

    /**
     * Check if a particular packet is known
     * \param id packet identifier
     * \return true if packet is known
     */
    bool knows(const PacketIdentifier& id) const;

private:
    std::size_t m_capacity = 1;

    struct by_packet {};
    using packet_index = boost::multi_index::hashed_unique<
        boost::multi_index::tag<by_packet>,
        boost::multi_index::identity<PacketIdentifier>,
        std::hash<PacketIdentifier>
    >;
    struct by_queue {};
    using queue_index = boost::multi_index::sequenced<boost::multi_index::tag<by_queue>>;

    using container_type = boost::multi_index_container<PacketIdentifier,
          boost::multi_index::indexed_by<queue_index, packet_index>>;
    container_type m_identifiers;
};

} // namespace geonet
} // namespace vanetza

#endif /* GBC_MEMORY_HPP_032N8PRJ */

