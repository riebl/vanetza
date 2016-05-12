#include "ethernet_header.hpp"
#include <algorithm>
#include <cassert>
#include <stdexcept>

namespace vanetza
{

ByteBuffer create_ethernet_header(const MacAddress& dest, const MacAddress& src, uint16be_t proto)
{
    ByteBuffer buffer;
    buffer.reserve(EthernetHeader::length_bytes);
    auto inserter = std::back_inserter(buffer);
    std::copy(dest.octets.begin(), dest.octets.end(), inserter);
    std::copy(src.octets.begin(), src.octets.end(), inserter);
    uint16_t host_proto = proto.host();
    inserter = (host_proto >> 8) & 0xff;
    inserter = host_proto & 0xff;
    assert(buffer.size() == EthernetHeader::length_bytes);
    return buffer;
}

ByteBuffer create_ethernet_header(const EthernetHeader& hdr)
{
    return create_ethernet_header(hdr.destination, hdr.source, hdr.type);
}

} // namespace vanetza

