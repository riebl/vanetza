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

extern const std::size_t MacAddress::scNumOctets;

MacAddress::MacAddress()
{
    std::fill_n(mOctets, scNumOctets, 0x00);
}

MacAddress::MacAddress(std::initializer_list<uint8_t> args)
{
    assert(args.size() == scNumOctets);
    std::copy_n(args.begin(), std::min(args.size(), scNumOctets), mOctets);
}

bool parseMacAddress(const std::string& str, MacAddress& addr)
{
    using namespace boost;
    static const unsigned scNumSeparators = MacAddress::scNumOctets - 1;
    static const unsigned scRequiredLength = MacAddress::scNumOctets* 2 + scNumSeparators;
    bool parsed = false;

    if (str.size() == scRequiredLength) {
        std::vector<std::string> octets;
        algorithm::split(octets, str, algorithm::is_any_of(":"));
        if (octets.size() == MacAddress::scNumOctets) {
            uint8_t* pCurrentOctet = addr.mOctets;
            for (const std::string& octet : octets) {
                *pCurrentOctet = strtol(octet.c_str(), nullptr, 16);
                ++pCurrentOctet;
            }
            parsed = true;
        }
    }

    return parsed;
}

void assignAddr(sockaddr_ll& sock, const MacAddress& mac)
{
    assert(ETHER_ADDR_LEN == MacAddress::scNumOctets);
    std::copy_n(mac.mOctets, MacAddress::scNumOctets, sock.sll_addr);
}

std::ostream& operator<<(std::ostream& os, const MacAddress& addr)
{
    os << std::hex;
    os << unsigned(addr.mOctets[0]);
    for (unsigned i = 1; i < addr.scNumOctets; ++i) {
        os << ":" << unsigned(addr.mOctets[i]);
    }
    os << std::dec;
    return os;
}
