#ifndef MAC_ADDRESS_HPP_FDINBLBS
#define MAC_ADDRESS_HPP_FDINBLBS

#include <boost/operators.hpp>
#include <array>
#include <cstddef>
#include <cstdint>
#include <initializer_list>
#include <ostream>
#include <string>

struct sockaddr_ll;

namespace vanetza
{

class MacAddress : public boost::equality_comparable<MacAddress>
{
public:
    MacAddress();
    MacAddress(std::initializer_list<uint8_t> args);

    std::array<uint8_t, 6> octets;
};

bool operator==(const MacAddress& lhs, const MacAddress& rhs);

bool parseMacAddress(const std::string&, MacAddress&);
void assignAddr(sockaddr_ll&, const MacAddress&);
std::ostream& operator<<(std::ostream& os, const MacAddress&);

/**
 * Derive a MAC address from an arbitrary integral value.
 * \param value used to derive MAC address, it's size does not matter
 * \return New MAC address
 */
template<typename T>
MacAddress createMacAddress(T value)
{
    MacAddress mac;
    const std::size_t octets = mac.octets.size();
    for (std::size_t i = octets - std::min(octets, sizeof(T)); i < octets; ++i) {
        mac.octets[i] = (value >> (8 * i)) & 0xff;
    }
    return mac;
}

} // namespace vanetza

#endif /* MAC_ADDRESS_HPP_FDINBLBS */
