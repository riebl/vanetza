#ifndef ETHERTYPE_HPP_ED3SIJFX
#define ETHERTYPE_HPP_ED3SIJFX

#include <vanetza/common/byte_order.hpp>

namespace vanetza
{
namespace access
{

using EtherType = uint16be_t;

namespace ethertype
{

static const EtherType GeoNetworking = host_cast<uint16_t>(0x8947);
static const EtherType WSMP = host_cast<uint16_t>(0x88DC);

} // namespace ethertype

} // namespace access
} // namespace vanetza

#endif /* ETHERTYPE_HPP_ED3SIJFX */

