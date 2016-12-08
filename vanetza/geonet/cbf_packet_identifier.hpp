#ifndef CBF_PACKET_IDENTIFIER_HPP_HC6PLCML
#define CBF_PACKET_IDENTIFIER_HPP_HC6PLCML

#include <vanetza/geonet/address.hpp>
#include <vanetza/geonet/sequence_number.hpp>
#include <functional>
#include <tuple>

namespace vanetza
{
namespace geonet
{

class CbfPacket;

using CbfPacketIdentifier = std::tuple<Address, SequenceNumber>;
CbfPacketIdentifier identifier(const CbfPacket&);
CbfPacketIdentifier identifier(const Address&, SequenceNumber);

} // namespace geonet
} // namespace vanetza

namespace std
{
/// std::hash specialization for CbfPacketIdentifier
template<> struct hash<vanetza::geonet::CbfPacketIdentifier>
{
    size_t operator()(const vanetza::geonet::CbfPacketIdentifier&) const;
};
} // namespace std

#endif /* CBF_PACKET_IDENTIFIER_HPP_HC6PLCML */

