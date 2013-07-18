#include "mac_address.hpp"
#include <boost/algorithm/string/classification.hpp>
#include <boost/algorithm/string/split.hpp>
#include <algorithm>
#include <cassert>
#include <cstdlib>
#include <string>
#include <vector>
#include <net/ethernet.h>
#include <netpacket/packet.h>

MacAddress::MacAddress()
{
    std::fill_n(octets.begin(), octets.size(), 0x00);
}

MacAddress::MacAddress(std::initializer_list<uint8_t> args)
{
    assert(args.size() == octets.size());
    std::copy_n(args.begin(), std::min(args.size(), octets.size()), octets.begin());
}
}

bool parseMacAddress(const std::string& str, MacAddress& addr)
{
    using namespace boost;
    static const unsigned scNumSeparators = addr.octets.size() - 1;
    static const unsigned scRequiredLength = addr.octets.size() * 2 + scNumSeparators;
    bool parsed = false;

    if (str.size() == scRequiredLength) {
        std::vector<std::string> octets;
        algorithm::split(octets, str, algorithm::is_any_of(":"));
        if (octets.size() == addr.octets.size()) {
            auto outputOctet = addr.octets.begin();
            for (const std::string& octet : octets) {
                *outputOctet = strtol(octet.c_str(), nullptr, 16);
                ++outputOctet;
            }
            parsed = true;
        }
    }

    return parsed;
}

void assignAddr(sockaddr_ll& sock, const MacAddress& mac)
{
    assert(ETHER_ADDR_LEN == mac.octets.size());
    std::copy_n(mac.octets.begin(), mac.octets.size(), sock.sll_addr);
}

std::ostream& operator<<(std::ostream& os, const MacAddress& addr)
{
    os << std::hex;
    os << unsigned(addr.octets[0]);
    for (unsigned i = 1; i < addr.octets.size(); ++i) {
        os << ":" << unsigned(addr.octets[i]);
    }
    os << std::dec;
    return os;
}
