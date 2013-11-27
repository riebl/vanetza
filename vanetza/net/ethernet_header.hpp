#ifndef ETHERNET_HEADER_HPP_
#define ETHERNET_HEADER_HPP_

#include <vanetza/common/byte_buffer.hpp>
#include <vanetza/common/byte_order.hpp>
#include <cstddef>

namespace vanetza
{

class MacAddress;

ByteBuffer createEthernetHeader(const MacAddress& dest, const MacAddress& src, uint16be_t proto);
std::size_t getEthernetHeaderLength();

} // namespace vanetza

#endif // ETHERNET_HEADER_HPP_

