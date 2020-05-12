#include <vanetza/geonet/cbf_packet_identifier.hpp>
#include <vanetza/geonet/cbf_packet_buffer.hpp>

namespace vanetza
{
namespace geonet
{

CbfPacketIdentifier identifier(const CbfPacket& packet)
{
    return identifier(packet.source(), packet.sequence_number());
}

CbfPacketIdentifier identifier(const Address& source, SequenceNumber sn)
{
    return std::make_tuple(source, sn);
}

} // namespace geonet
} // namespace vanetza

namespace std
{

size_t hash<vanetza::geonet::CbfPacketIdentifier>::operator()(const vanetza::geonet::CbfPacketIdentifier& id) const
{
    using vanetza::geonet::Address;
    using vanetza::geonet::SequenceNumber;
    static_assert(tuple_size<vanetza::geonet::CbfPacketIdentifier>::value == 2, "Unexpected identifier tuple");

    std::size_t seed = 0;
    const Address& source = get<0>(id);
    boost::hash_combine(seed, std::hash<Address>()(source));
    const SequenceNumber& sn = get<1>(id);
    boost::hash_combine(seed, static_cast<SequenceNumber::value_type>(sn));
    return seed;
}

} // namespace std
