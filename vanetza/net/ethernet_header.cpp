#include "ethernet_header.hpp"
#include "mac_address.hpp"
#include "vanetza/common/byte_buffer.hpp"
#include <algorithm>
#include <cassert>
#include <net/ethernet.h>

ByteBuffer createEthernetHeader(const MacAddress& dest, const MacAddress& src, uint16be_t proto)
{
    ByteBuffer buffer(sizeof(ethhdr));
    assert(buffer.size() == ETHER_HDR_LEN);

    ethhdr* hdr = reinterpret_cast<ethhdr*>(&buffer[0]);
    std::copy(dest.octets.begin(), dest.octets.end(), hdr->h_dest);
    std::copy(src.octets.begin(), src.octets.end(), hdr->h_source);
    hdr->h_proto = proto.get();

    return buffer;
}

std::size_t getEthernetHeaderLength()
{
    return ETHER_HDR_LEN;
}
