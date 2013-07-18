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

#endif /* MAC_ADDRESS_HPP_FDINBLBS */
